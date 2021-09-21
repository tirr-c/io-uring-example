use libc::{c_int, c_uint, c_void};

use std::os::unix::prelude::*;
use std::sync::atomic::{self, Ordering};

pub mod io_uring;

unsafe fn io_uring_setup(entries: u32, p: *mut io_uring::io_uring_params) -> c_int {
    libc::syscall(libc::SYS_io_uring_setup, entries, p) as c_int
}

unsafe fn io_uring_enter(fd: c_uint, to_submit: c_uint, min_complete: c_uint, flags: c_uint) -> c_int {
    libc::syscall(libc::SYS_io_uring_enter, fd, to_submit, min_complete, flags, std::ptr::null::<c_void>(), 0 as libc::size_t) as c_int
}

#[derive(Debug, Copy, Clone)]
struct MemoryMapSize {
    sq: usize,
    cq: usize,
    sqe: usize,
}

impl MemoryMapSize {
    fn calculate(params: &io_uring::io_uring_params) -> Self {
        let is_single_mmap = params.features & io_uring::IORING_FEAT_SINGLE_MMAP != 0;
        let mut sq = params.sq_off.array as usize + params.sq_entries as usize * std::mem::size_of::<u32>();
        let mut cq = params.cq_off.cqes as usize + params.cq_entries as usize * std::mem::size_of::<io_uring::io_uring_cqe>();
        let sqe = params.sq_entries as usize * std::mem::size_of::<io_uring::io_uring_sqe>();

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
    fn new(entries: u32) -> Result<Self, Error> {
        let mut uring = unsafe {
            let mut params = std::mem::MaybeUninit::<io_uring::io_uring_params>::zeroed()
                .assume_init();
            let fd = io_uring_setup(entries, &mut params);
            if fd == -1 {
                let errno = *libc::__errno_location();
                return Err(Error::Other(errno));
            }

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

        let is_single_mmap = params.features & io_uring::IORING_FEAT_SINGLE_MMAP != 0;
        let sizes = MemoryMapSize::calculate(params);

        uring.sq_raw = unsafe {
            let sq_raw = libc::mmap(
                std::ptr::null_mut(), sizes.sq, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE, fd, io_uring::IORING_OFF_SQ_RING as i64,
            );
            if sq_raw == libc::MAP_FAILED {
                let errno = *libc::__errno_location();
                return Err(Error::MapFailed(errno));
            }
            sq_raw
        };

        uring.cq_raw = if is_single_mmap {
            uring.sq_raw
        } else {
            unsafe {
                let cq_raw = libc::mmap(
                    std::ptr::null_mut(), sizes.cq, libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE, fd, io_uring::IORING_OFF_CQ_RING as i64,
                );
                if cq_raw == libc::MAP_FAILED {
                    let errno = *libc::__errno_location();
                    return Err(Error::MapFailed(errno));
                }
                cq_raw
            }
        };

        uring.sqe_raw = unsafe {
            let sqe_raw = libc::mmap(
                std::ptr::null_mut(), sizes.sqe, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE, fd, io_uring::IORING_OFF_SQES as i64,
            );
            if sqe_raw == libc::MAP_FAILED {
                let errno = *libc::__errno_location();
                return Err(Error::MapFailed(errno));
            }
            sqe_raw
        };

        Ok(uring)
    }

    fn queue(&mut self) -> (RawSubmissionQueue, RawCompletionQueue) {
        let sq_ptr = self.sq_raw as *mut u8;
        let cq_ptr = self.cq_raw as *mut u8;
        let sqes = self.sqe_raw as *mut _;

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

    pub fn len(&self) -> u32 {
        unsafe {
            let head = (*self.head).load(Ordering::Acquire);
            let tail = (*self.tail).load(Ordering::Relaxed);
            tail - head
        }
    }

    pub fn empty_entries(&self) -> u32 {
        self.entry_count() - self.len()
    }

    pub unsafe fn enqueue(&self, sqe: io_uring::io_uring_sqe) -> Result<(), Error> {
        let head = (*self.head).load(Ordering::Acquire);
        let tail = (*self.tail).load(Ordering::Relaxed);
        let mask = *self.mask;
        let index = tail & mask;
        if head != tail && (head & mask) == index {
            return Err(Error::SubmissionQueueFull);
        }

        self.sqes.add(index as usize).write(sqe);
        self.indices.add(index as usize).write(index);

        (*self.tail).store(tail + 1, Ordering::Release);
        Ok(())
    }

    fn submit_inner(&self, to_submit: u32, min_complete: u32, flags: u32) -> Result<u32, Error> {
        let submit_count = unsafe {
            io_uring_enter(self.fd as u32, to_submit, min_complete, flags)
        };
        if submit_count < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(Error::SubmissionFailed(errno));
        }
        Ok(submit_count as u32)
    }

    pub fn submit(&self, to_submit: u32) -> Result<u32, Error> {
        self.submit_inner(to_submit, 0, 0)
    }

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

    pub fn len(&self) -> u32 {
        unsafe {
            let head = (*self.head).load(Ordering::Acquire);
            let tail = (*self.tail).load(Ordering::Relaxed);
            tail - head
        }
    }

    pub fn empty_entries(&self) -> u32 {
        self.entry_count() - self.len()
    }

    pub unsafe fn dequeue(&self) -> Option<io_uring::io_uring_cqe> {
        let head = (*self.head).load(Ordering::Acquire);
        let tail = (*self.tail).load(Ordering::Relaxed);
        if head == tail {
            return None;
        }

        let mask = *self.mask;
        let index = head & mask;
        let cqe = self.cqes.add(index as usize).read();

        (*self.head).store(head + 1, Ordering::Release);
        Some(cqe)
    }
}

fn main() {
    let mut uring = IoUring::new(2).expect("Failed to request ring buffer");
    let (sq, cq) = uring.queue();

    let file = std::fs::File::open("test").unwrap();

    let mut sqe = unsafe { std::mem::MaybeUninit::<io_uring::io_uring_sqe>::zeroed().assume_init() };
    let mut buf = vec![0u8; 4096];
    let iovecs = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    sqe.opcode = io_uring::IORING_OP_READV as u8;
    sqe.fd = file.as_raw_fd();
    sqe.__bindgen_anon_1.off = 0;
    sqe.__bindgen_anon_2.addr = &iovecs as *const _ as usize as u64;
    sqe.len = 1;

    unsafe { sq.enqueue(sqe).unwrap() };
    let submitted_count = sq.submit_and_wait(1, 1).unwrap();
    eprintln!("Submitted {} request(s)", submitted_count);
    let cqe = unsafe { cq.dequeue().unwrap() };
    dbg!(&cqe);

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
