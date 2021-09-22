use libc::{c_int, c_uint, c_void};

use std::os::unix::prelude::*;
use std::sync::atomic::{self, Ordering};

pub mod io_uring;

/// `io_uring_setup` 시스템 콜 래퍼입니다.
unsafe fn io_uring_setup(entries: u32, p: *mut io_uring::io_uring_params) -> c_int {
    libc::syscall(libc::SYS_io_uring_setup, entries, p) as c_int
}

/// `io_uring_enter` 시스템 콜 래퍼입니다.
unsafe fn io_uring_enter(
    fd: c_uint,
    to_submit: c_uint,
    min_complete: c_uint,
    flags: c_uint,
) -> c_int {
    libc::syscall(
        libc::SYS_io_uring_enter,
        fd,
        to_submit,
        min_complete,
        flags,
        std::ptr::null::<c_void>(), // arg
        0 as libc::size_t, // argsz
    ) as c_int
}

#[derive(Debug, Copy, Clone)]
struct MemoryMapSize {
    sq: usize,
    cq: usize,
    sqe: usize,
}

impl MemoryMapSize {
    /// io_uring에 필요한 메모리 영역의 크기를 계산합니다.
    fn calculate(params: &io_uring::io_uring_params) -> Self {
        let is_single_mmap = params.features & io_uring::IORING_FEAT_SINGLE_MMAP != 0;

        // SQ의 크기. SQE 인덱스 링 버퍼가 전체 구조체의 마지막에 위치하기 때문에, 버퍼의 오프셋에
        // 버퍼 크기를 더하면 전체 구조체 크기를 알 수 있다.
        let mut sq =
            params.sq_off.array as usize + params.sq_entries as usize * std::mem::size_of::<u32>();
        // CQ의 크기. SQ와 마찬가지로 CQE 링 버퍼가 전체 구조체의 마지막에 위치한다.
        let mut cq = params.cq_off.cqes as usize
            + params.cq_entries as usize * std::mem::size_of::<io_uring::io_uring_cqe>();
        // 실제 SQE가 들어갈 메모리 영역의 크기.
        let sqe = params.sq_entries as usize * std::mem::size_of::<io_uring::io_uring_sqe>();

        // IORING_FEAT_SINGLE_MMAP이 설정되어 있으면 SQ와 CQ 중 큰 쪽으로 한 번만 mmap한다. 자세한
        // 내용은 `IoUring::new` 참고.
        if is_single_mmap {
            let val = std::cmp::max(sq, cq);
            sq = val;
            cq = val;
        }

        Self { sq, cq, sqe }
    }
}

#[derive(Debug)]
struct IoUring {
    fd: RawFd,
    params: io_uring::io_uring_params,
    sq_raw: *mut c_void,
    cq_raw: *mut c_void,
    sqe_raw: *mut c_void,
}

#[derive(Debug)]
pub enum Error {
    MapFailed(i32),
    SubmissionQueueFull,
    SubmissionFailed(i32),
    Other(i32),
}

impl IoUring {
    /// `entries` 개의 SQE를 가질 수 있는 io_uring 구조체를 만듭니다.
    fn new(entries: u32) -> Result<Self, Error> {
        let mut uring = unsafe {
            // 커널에 링 버퍼를 부탁한다. 커널은 버퍼를 만든 뒤 관련 파라미터를 돌려준다.
            let mut params =
                std::mem::MaybeUninit::<io_uring::io_uring_params>::zeroed().assume_init();
            let fd = io_uring_setup(entries, &mut params);
            if fd == -1 {
                let errno = *libc::__errno_location();
                return Err(Error::Other(errno));
            }

            // 먼저 IoUring 값을 만들어 두면 중간에 실패하더라도 IoUring이 drop되면서 남은 자원을
            // 회수하도록 할 수 있다.
            Self {
                fd,
                params,
                sq_raw: std::ptr::null_mut(),
                cq_raw: std::ptr::null_mut(),
                sqe_raw: std::ptr::null_mut(),
            }
        };
        let fd = uring.fd;
        let params = &uring.params;

        // Linux >=5.4에서는 mmap 한 번에 SQ와 CQ가 모두 매핑되어, 쓸 때는 SQ에 쓰고 읽을 때는 CQ를
        // 읽게 된다. features 필드의 IORING_FEAT_SINGLE_MMAP 비트를 확인해 만약 그렇다면 두 개의
        // 큐 중에 큰 쪽으로 한 번만 mmap한다.
        let is_single_mmap = params.features & io_uring::IORING_FEAT_SINGLE_MMAP != 0;
        let sizes = MemoryMapSize::calculate(params);

        uring.sq_raw = unsafe {
            let sq_raw = libc::mmap(
                std::ptr::null_mut(),
                sizes.sq,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                io_uring::IORING_OFF_SQ_RING as i64,
            );
            if sq_raw == libc::MAP_FAILED {
                let errno = *libc::__errno_location();
                return Err(Error::MapFailed(errno));
            }
            sq_raw
        };

        uring.cq_raw = if is_single_mmap {
            // SQ와 CQ가 같은 주소를 공유
            uring.sq_raw
        } else {
            // CQ를 따로 매핑해야 함
            unsafe {
                let cq_raw = libc::mmap(
                    std::ptr::null_mut(),
                    sizes.cq,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    io_uring::IORING_OFF_CQ_RING as i64,
                );
                if cq_raw == libc::MAP_FAILED {
                    let errno = *libc::__errno_location();
                    return Err(Error::MapFailed(errno));
                }
                cq_raw
            }
        };

        // 실제 SQE가 들어갈 버퍼를 매핑한다.
        uring.sqe_raw = unsafe {
            let sqe_raw = libc::mmap(
                std::ptr::null_mut(),
                sizes.sqe,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                io_uring::IORING_OFF_SQES as i64,
            );
            if sqe_raw == libc::MAP_FAILED {
                let errno = *libc::__errno_location();
                return Err(Error::MapFailed(errno));
            }
            sqe_raw
        };

        Ok(uring)
    }

    /// io_uring 구조체의 정보를 참고해 SQ와 CQ에 접근할 수 있도록 합니다.
    fn queue(&mut self) -> (RawSubmissionQueue, RawCompletionQueue) {
        let sq_ptr = self.sq_raw as *mut u8;
        let cq_ptr = self.cq_raw as *mut u8;
        let sqes = self.sqe_raw as *mut io_uring::io_uring_sqe;

        let sq = unsafe {
            RawSubmissionQueue {
                _holder: Default::default(),
                fd: self.fd,
                head: sq_ptr.add(self.params.sq_off.head as usize) as *const _,
                tail: sq_ptr.add(self.params.sq_off.tail as usize) as *const _,
                mask: sq_ptr.add(self.params.sq_off.ring_mask as usize) as *const _,
                flags: sq_ptr.add(self.params.sq_off.flags as usize) as *const _,
                dropped_count: sq_ptr.add(self.params.sq_off.dropped as usize) as *const _,
                indices: sq_ptr.add(self.params.sq_off.array as usize) as *mut _,
                sqes,
            }
        };

        let cq = unsafe {
            RawCompletionQueue {
                _holder: Default::default(),
                fd: self.fd,
                head: cq_ptr.add(self.params.cq_off.head as usize) as *const _,
                tail: cq_ptr.add(self.params.cq_off.tail as usize) as *const _,
                mask: cq_ptr.add(self.params.cq_off.ring_mask as usize) as *const _,
                flags: cq_ptr.add(self.params.cq_off.flags as usize) as *const _,
                overflow_count: cq_ptr.add(self.params.cq_off.overflow as usize) as *const _,
                cqes: cq_ptr.add(self.params.cq_off.cqes as usize) as *mut _,
            }
        };

        (sq, cq)
    }
}

impl AsRawFd for IoUring {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for IoUring {
    fn drop(&mut self) {
        // 여기서 사용한 리소스, 또는 만들다 만 리소스의 정리가 일어난다.
        // fd와 params는 항상 초기화되어 있다고 가정한다.
        let is_single_mmap = self.params.features & io_uring::IORING_FEAT_SINGLE_MMAP != 0;
        let sizes = MemoryMapSize::calculate(&self.params);
        unsafe {
            if !self.sq_raw.is_null() {
                libc::munmap(self.sq_raw, sizes.sq);
                self.sq_raw = std::ptr::null_mut();
            }
            if !is_single_mmap && !self.cq_raw.is_null() {
                libc::munmap(self.cq_raw, sizes.cq);
                self.cq_raw = std::ptr::null_mut();
            }
            if !self.sqe_raw.is_null() {
                libc::munmap(self.sqe_raw, sizes.sqe);
                self.sqe_raw = std::ptr::null_mut();
            }
            libc::close(self.fd);
        }
    }
}

#[derive(Debug)]
pub struct RawSubmissionQueue<'q> {
    _holder: std::marker::PhantomData<&'q ()>,
    fd: RawFd,
    head: *const atomic::AtomicU32,
    tail: *const atomic::AtomicU32,
    mask: *const u32,
    flags: *const atomic::AtomicU32,
    dropped_count: *const atomic::AtomicU32,
    indices: *mut u32,
    sqes: *mut io_uring::io_uring_sqe,
}

impl RawSubmissionQueue<'_> {
    fn entry_count(&self) -> u32 {
        unsafe { *self.mask + 1 }
    }

    /// 큐에 남아 있는 SQE의 개수를 가져옵니다.
    pub fn len(&self) -> u32 {
        unsafe {
            let head = (*self.head).load(Ordering::Acquire);
            let tail = (*self.tail).load(Ordering::Relaxed);
            tail - head
        }
    }

    /// 큐에 비어 있는 자리의 개수를 가져옵니다.
    pub fn empty_entries(&self) -> u32 {
        self.entry_count() - self.len()
    }

    /// 큐에 SQE 하나를 넣습니다.
    ///
    /// # Safety
    /// `sqe`는 해당하는 CQE가 돌아올 때까지 올바른 값을 갖고 있어야 합니다.
    pub unsafe fn enqueue(&mut self, sqe: io_uring::io_uring_sqe) -> Result<(), Error> {
        let head = (*self.head).load(Ordering::Acquire);
        let tail = (*self.tail).load(Ordering::Relaxed);
        let mask = *self.mask;
        let index = tail & mask;
        // 링 버퍼가 가득 찼는지 확인한다.
        if head != tail && (head & mask) == index {
            return Err(Error::SubmissionQueueFull);
        }

        // 버퍼 끝에 SQE를 넣는다.
        self.sqes.add(index as usize).write(sqe);
        self.indices.add(index as usize).write(index);
        (*self.tail).store(tail + 1, Ordering::Release);

        Ok(())
    }

    /// 큐의 SQE를 처리하도록 커널에 요청합니다.
    fn submit_inner(&self, to_submit: u32, min_complete: u32, flags: u32) -> Result<u32, Error> {
        let submit_count =
            unsafe { io_uring_enter(self.fd as u32, to_submit, min_complete, flags) };
        if submit_count < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(Error::SubmissionFailed(errno));
        }
        Ok(submit_count as u32)
    }

    /// 큐의 SQE를 처리하도록 커널에 요청합니다. 이 함수는 커널에 요청한 후 바로 리턴합니다.
    pub fn submit(&self, to_submit: u32) -> Result<u32, Error> {
        self.submit_inner(to_submit, 0, 0)
    }

    /// 큐의 SQE를 처리하도록 커널에 요청합니다. 이 함수는 커널에 요청한 후 `min_complete`개의
    /// CQE가 돌아올 때까지 리턴하지 않습니다.
    pub fn submit_and_wait(&self, to_submit: u32, min_complete: u32) -> Result<u32, Error> {
        self.submit_inner(to_submit, min_complete, io_uring::IORING_ENTER_GETEVENTS)
    }
}

#[derive(Debug)]
pub struct RawCompletionQueue<'q> {
    _holder: std::marker::PhantomData<&'q ()>,
    fd: RawFd,
    head: *const atomic::AtomicU32,
    tail: *const atomic::AtomicU32,
    mask: *const u32,
    overflow_count: *const atomic::AtomicU32,
    flags: *const atomic::AtomicU32,
    cqes: *mut io_uring::io_uring_cqe,
}

impl RawCompletionQueue<'_> {
    fn entry_count(&self) -> u32 {
        unsafe { *self.mask + 1 }
    }

    /// 큐에 남아 있는 CQE의 개수를 가져옵니다.
    pub fn len(&self) -> u32 {
        unsafe {
            let head = (*self.head).load(Ordering::Acquire);
            let tail = (*self.tail).load(Ordering::Relaxed);
            tail - head
        }
    }

    /// 큐에 남아 있는 SQE의 개수를 가져옵니다.
    pub fn empty_entries(&self) -> u32 {
        self.entry_count() - self.len()
    }

    /// 큐에서 CQE 하나를 꺼냅니다.
    pub fn dequeue(&mut self) -> Option<io_uring::io_uring_cqe> {
        unsafe {
            let head = (*self.head).load(Ordering::Acquire);
            let tail = (*self.tail).load(Ordering::Relaxed);
            // 링 버퍼가 비어 있는지 확인한다.
            if head == tail {
                return None;
            }

            let mask = *self.mask;
            let index = head & mask;

            // 링 버퍼 앞에서 CQE 하나를 꺼낸다.
            let cqe = self.cqes.add(index as usize).read();
            (*self.head).store(head + 1, Ordering::Release);

            Some(cqe)
        }
    }
}

fn main() {
    let mut uring = IoUring::new(2).expect("Failed to request ring buffer");
    let (mut sq, mut cq) = uring.queue();

    let file = std::fs::File::open("test").unwrap();

    // preadv 명령을 담은 SQE를 초기화한다.
    let mut sqe =
        unsafe { std::mem::MaybeUninit::<io_uring::io_uring_sqe>::zeroed().assume_init() };
    let mut buf = vec![0u8; 4096];
    let iovecs = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    sqe.opcode = io_uring::IORING_OP_READV as u8; // preadv
    sqe.fd = file.as_raw_fd(); // fd
    sqe.__bindgen_anon_1.off = 0; // offset
    sqe.__bindgen_anon_2.addr = &iovecs as *const _ as usize as u64; // iov
    sqe.len = 1; // iovcnt

    // SQE를 넣고 처리가 끝날 때까지 기다린 뒤 CQE를 꺼낸다.
    unsafe { sq.enqueue(sqe).unwrap() };
    let submitted_count = sq.submit_and_wait(1, 1).unwrap();
    eprintln!("Submitted {} request(s)", submitted_count);
    let cqe = cq.dequeue().unwrap();
    dbg!(&cqe);

    // preadv의 결과를 확인한다.
    let read_cnt = cqe.res;
    if read_cnt < 0 {
        let errno = -read_cnt;
        eprintln!("Read failed (errno {})", errno);
        std::process::exit(1);
    }

    let read_cnt = read_cnt as usize;
    let data = &buf[..read_cnt];
    eprintln!("Read {} byte(s)", read_cnt);
    dbg!(data);
}
