use std::cell::UnsafeCell;
use std::fmt::Debug;
use std::os::unix::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use libc::{c_int, c_uint, c_void};
use nix::{
    errno,
    fcntl,
    sys::{eventfd, mman},
    unistd,
};

pub mod sys;
pub use sys::io_uring_cqe as RawCqe;
pub use sys::io_uring_sqe as RawSqe;

mod ops;
use ops::{
    SubmissionOp,
    CompletionSender,
};
pub use ops::{
    CompletionReceiver,
    VectoredRead,
    VectoredReadResult,
};

/// `io_uring_setup` 시스템 콜 래퍼입니다.
unsafe fn io_uring_setup(entries: u32, p: *mut sys::io_uring_params) -> c_int {
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
        0 as libc::size_t,          // argsz
    ) as c_int
}

unsafe fn io_uring_register(
    fd: c_uint,
    opcode: c_uint,
    arg: *mut c_void,
    nr_args: c_uint,
) -> c_int {
    libc::syscall(
        libc::SYS_io_uring_register,
        fd,
        opcode,
        arg,
        nr_args,
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
    fn calculate(params: &sys::io_uring_params) -> Self {
        let is_single_mmap = params.features & sys::IORING_FEAT_SINGLE_MMAP != 0;

        // SQ의 크기. SQE 인덱스 링 버퍼가 전체 구조체의 마지막에 위치하기 때문에, 버퍼의 오프셋에
        // 버퍼 크기를 더하면 전체 구조체 크기를 알 수 있다.
        let mut sq =
            params.sq_off.array as usize + params.sq_entries as usize * std::mem::size_of::<u32>();
        // CQ의 크기. SQ와 마찬가지로 CQE 링 버퍼가 전체 구조체의 마지막에 위치한다.
        let mut cq = params.cq_off.cqes as usize
            + params.cq_entries as usize * std::mem::size_of::<RawCqe>();
        // 실제 SQE가 들어갈 메모리 영역의 크기.
        let sqe = params.sq_entries as usize * std::mem::size_of::<RawSqe>();

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
pub struct IoUring {
    meta: Arc<IoUringMeta>,
    sq: IoUringSq,
    cq: IoUringCq,
}

#[derive(Debug)]
struct IoUringMeta {
    fd: RawFd,
    params: sys::io_uring_params,
    pending: AtomicU32,
    sq_mmap_count: AtomicU8,
    sq_dropped: AtomicBool,
    eventfd: RawFd,
}

impl Drop for IoUringMeta {
    fn drop(&mut self) {
        unsafe {
            io_uring_register(self.fd as u32, sys::IORING_UNREGISTER_EVENTFD, std::ptr::null_mut(), 0);
        }
        unistd::close(self.fd).ok();
        unistd::close(self.eventfd).ok();
    }
}

impl IoUringMeta {
    fn new(fd: RawFd, params: sys::io_uring_params) -> Self {
        let is_single_mmap = params.features & sys::IORING_FEAT_SINGLE_MMAP != 0;

        let mut eventfd = eventfd::eventfd(0, eventfd::EfdFlags::empty())
            .expect("eventfd creation failed");
        unsafe {
            io_uring_register(fd as u32, sys::IORING_REGISTER_EVENTFD, &mut eventfd as *mut _ as *mut c_void, 1);
        }

        Self {
            fd,
            params,
            pending: AtomicU32::new(0),
            sq_mmap_count: AtomicU8::new(if is_single_mmap { 2 } else { 1 }),
            sq_dropped: AtomicBool::new(false),
            eventfd,
        }
    }

    fn notify(&self) {
        static BUF: [u8; 8] = u64::to_ne_bytes(1);
        unistd::write(self.eventfd, &BUF).ok();
    }
}

impl IoUringMeta {
    fn map_sizes(&self) -> MemoryMapSize {
        MemoryMapSize::calculate(&self.params)
    }
}

pub struct IoUringSq(Arc<IoUringSqInner>);

impl Debug for IoUringSq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoUringSq").finish_non_exhaustive()
    }
}

impl From<IoUringSqInner> for IoUringSq {
    fn from(val: IoUringSqInner) -> Self {
        Self(Arc::new(val))
    }
}

impl IoUringSq {
    pub fn merge(self, cq: IoUringCq) -> IoUring {
        IoUring {
            meta: self.0.meta.clone(),
            sq: self,
            cq,
        }
    }
}

impl IoUringSq {
    pub fn enqueue<Op: SubmissionOp>(&self, entry: Op) -> Result<CompletionReceiver<Op>, Error> {
        let (sqe, rx) = entry.into_sqe();
        unsafe { self.0.enqueue(sqe) }?;
        Ok(rx)
    }

    pub fn submit_all(&self) -> Result<u32, Error> {
        self.0.submit_all()
    }
}

struct IoUringSqInner {
    meta: Arc<IoUringMeta>,
    sq_raw: *mut c_void,
    sqe_raw: *mut c_void,
    updating_tail: AtomicU32,
}

unsafe impl Send for IoUringSqInner {}
unsafe impl Sync for IoUringSqInner {}

impl Drop for IoUringSqInner {
    fn drop(&mut self) {
        let submit_result = self.submit_all();
        if submit_result.is_err() {
            // clean up remaining sqes
            let head = self.head_ref();
            let tail = self.tail_ref();
            let mask = *self.mask_ref();
            let last_head = head.load(Ordering::Acquire);
            let last_tail = tail.swap(last_head, Ordering::Release);
            self.meta.pending.fetch_sub(last_tail - last_head, Ordering::AcqRel);

            let array = self.array_ref();
            let sqe_raw = self.sqe_raw as *mut RawSqe;
            for idx in last_head..last_tail {
                unsafe {
                    let idx = *array.offset((idx & mask) as isize);
                    let sqe = sqe_raw.offset(idx as isize).read();
                    let sender = Box::from_raw(sqe.user_data as *mut CompletionSender);
                    drop(sender);
                }
            }
        }
        self.meta.sq_dropped.store(true, Ordering::Release);
        self.meta.notify();

        let sizes = self.meta.map_sizes();
        unsafe {
            if !self.sq_raw.is_null() {
                let count = self.meta.sq_mmap_count.fetch_sub(1, Ordering::AcqRel);
                if count == 1 {
                    mman::munmap(self.sq_raw, sizes.sq).ok();
                }
                self.sq_raw = std::ptr::null_mut();
            }
            if !self.sqe_raw.is_null() {
                mman::munmap(self.sqe_raw, sizes.sqe).ok();
                self.sqe_raw = std::ptr::null_mut();
            }
        }
    }
}

impl IoUringSqInner {
    fn sq_bytes_ptr(&self) -> *mut u8 {
        self.sq_raw as *mut u8
    }

    unsafe fn sq_offset_atomic(&self, offset: u32) -> &AtomicU32 {
        &*(self.sq_bytes_ptr().offset(offset as isize) as *const AtomicU32)
    }

    fn head_ref(&self) -> &AtomicU32 {
        unsafe { self.sq_offset_atomic(self.meta.params.sq_off.head) }
    }

    fn tail_ref(&self) -> &AtomicU32 {
        unsafe { self.sq_offset_atomic(self.meta.params.sq_off.tail) }
    }

    fn mask_ref(&self) -> &u32 {
        unsafe {
            &*(self.sq_bytes_ptr().offset(self.meta.params.sq_off.ring_mask as isize) as *const u32)
        }
    }

    fn array_ref(&self) -> *mut u32 {
        unsafe {
            self.sq_bytes_ptr().offset(self.meta.params.sq_off.array as isize) as *mut u32
        }
    }

    /// # Safety
    /// Unsynchronized access
    unsafe fn write_to_idx(&self, index: u32, sqe: RawSqe) {
        let mask = *self.mask_ref();
        let array_ptr = self.array_ref() as *const UnsafeCell<u32>;
        let sqe_ptr = self.sqe_raw as *const UnsafeCell<RawSqe>;

        let array_idx = index & mask;
        (*sqe_ptr.offset(array_idx as isize)).get().write(sqe);
        (*array_ptr.offset(array_idx as isize)).get().write(array_idx);
    }
}

impl IoUringSqInner {
    /// 큐에 SQE 하나를 넣습니다.
    ///
    /// # Safety
    /// `sqe`는 해당하는 CQE가 돌아올 때까지 올바른 값을 갖고 있어야 합니다.
    unsafe fn enqueue(&self, entry: RawSqe) -> Result<(), Error> {
        let head = self.head_ref();
        let tail = self.tail_ref();
        let updating_tail = &self.updating_tail;
        let mask = *self.mask_ref();

        let backoff = crossbeam_utils::Backoff::new();
        let index = loop {
            let index = updating_tail.load(Ordering::Acquire);
            let head = head.load(Ordering::Acquire);
            if head != index && (head & mask) == (index & mask) {
                return Err(Error::SubmissionQueueFull);
            }

            let result = updating_tail.compare_exchange(index, index.wrapping_add(1), Ordering::AcqRel, Ordering::Acquire);
            if result.is_err() {
                // 다른 스레드가 먼저 갱신했으므로 기다림
                backoff.spin();
            } else {
                break index;
            }
        };
        backoff.reset();

        self.meta.pending.fetch_add(1, Ordering::Relaxed);
        self.write_to_idx(index, entry);

        while tail.compare_exchange(index, index.wrapping_add(1), Ordering::AcqRel, Ordering::Acquire).is_err() {
            // 이전 스레드가 작업을 마칠 때까지 대기
            backoff.snooze();
        }

        Ok(())
    }

    fn submit_all(&self) -> Result<u32, Error> {
        let head = self.head_ref();
        let tail = self.tail_ref();
        let count = tail.load(Ordering::Acquire) - head.load(Ordering::Acquire);
        if count == 0 {
            return Ok(0);
        }

        let ret = unsafe { io_uring_enter(self.meta.fd as u32, count, 0, 0) };
        if ret < 0 {
            let errno = errno::errno();
            Err(Error::SubmissionFailed(errno))
        } else {
            Ok(ret as u32)
        }
    }
}

pub struct IoUringCq(IoUringCqInner);

impl Debug for IoUringCq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoUringCq").finish_non_exhaustive()
    }
}

impl From<IoUringCqInner> for IoUringCq {
    fn from(val: IoUringCqInner) -> Self {
        Self(val)
    }
}

impl IoUringCq {
    pub fn wait(&self) {
        let inner = &self.0;
        let mut buf = [0u8; 8];

        // make eventfd non-blocking
        let flags = fcntl::fcntl(inner.meta.eventfd, fcntl::FcntlArg::F_GETFL)
            .expect("cannot fcntl GETFL on eventfd");
        let mut flags = fcntl::OFlag::from_bits(flags).unwrap();
        if !flags.contains(fcntl::OFlag::O_NONBLOCK) {
            flags.set(fcntl::OFlag::O_NONBLOCK, true);
            fcntl::fcntl(inner.meta.eventfd, fcntl::FcntlArg::F_SETFL(flags)).ok();
        }

        loop {
            while let Some(cqe) = inner.dequeue() {
                let sender = cqe.user_data as *mut CompletionSender;
                unsafe {
                    if (*sender).channel.send(cqe).is_err() {
                        // 끊어졌으므로 여기서 할당 해제
                        let sender = Box::from_raw(sender);
                        drop(sender);
                    }
                }
            }

            let pending = inner.meta.pending.load(Ordering::Acquire);
            if pending == 0 && inner.meta.sq_dropped.load(Ordering::Acquire) {
                break;
            }

            let result = unistd::read(inner.meta.eventfd, &mut buf);
            if let Err(errno::Errno::EBUSY | errno::Errno::EWOULDBLOCK) = result {
                break;
            }
        }
    }

    pub fn run(&self) {
        let inner = &self.0;
        let mut buf = [0u8; 8];

        // make eventfd blocking
        let flags = fcntl::fcntl(inner.meta.eventfd, fcntl::FcntlArg::F_GETFL)
            .expect("cannot fcntl GETFL on eventfd");
        let mut flags = fcntl::OFlag::from_bits(flags).unwrap();
        if flags.contains(fcntl::OFlag::O_NONBLOCK) {
            flags.set(fcntl::OFlag::O_NONBLOCK, false);
            fcntl::fcntl(inner.meta.eventfd, fcntl::FcntlArg::F_SETFL(flags)).ok();
        }

        loop {
            while let Some(cqe) = inner.dequeue() {
                let sender = cqe.user_data as *mut CompletionSender;
                unsafe {
                    if (*sender).channel.send(cqe).is_err() {
                        // 끊어졌으므로 여기서 할당 해제
                        let sender = Box::from_raw(sender);
                        drop(sender);
                    }
                }
            }

            let pending = inner.meta.pending.load(Ordering::Acquire);
            if pending == 0 && inner.meta.sq_dropped.load(Ordering::Acquire) {
                break;
            }

            unistd::read(inner.meta.eventfd, &mut buf).ok();
        }
    }
}

impl IoUringCq {
    pub fn merge(self, sq: IoUringSq) -> IoUring {
        IoUring {
            meta: self.0.meta.clone(),
            sq,
            cq: self,
        }
    }
}

struct IoUringCqInner {
    meta: Arc<IoUringMeta>,
    cq_raw: *mut c_void,
}

unsafe impl Send for IoUringCqInner {}

impl Drop for IoUringCqInner {
    fn drop(&mut self) {
        let sizes = self.meta.map_sizes();
        unsafe {
            // FIXME
            if !self.cq_raw.is_null() {
                let count = self.meta.sq_mmap_count.fetch_sub(1, Ordering::AcqRel);
                if count == 1 {
                    mman::munmap(self.cq_raw, sizes.cq).ok();
                }
                self.cq_raw = std::ptr::null_mut();
            }
        }
    }
}

impl IoUringCqInner {
    fn cq_bytes_ptr(&self) -> *mut u8 {
        self.cq_raw as *mut u8
    }

    unsafe fn cq_offset_atomic(&self, offset: u32) -> &AtomicU32 {
        &*(self.cq_bytes_ptr().offset(offset as isize) as *const AtomicU32)
    }

    fn head_ref(&self) -> &AtomicU32 {
        unsafe { self.cq_offset_atomic(self.meta.params.cq_off.head) }
    }

    fn tail_ref(&self) -> &AtomicU32 {
        unsafe { self.cq_offset_atomic(self.meta.params.cq_off.tail) }
    }

    fn mask_ref(&self) -> &u32 {
        unsafe {
            &*(self.cq_bytes_ptr().offset(self.meta.params.cq_off.ring_mask as isize) as *const u32)
        }
    }

    /// # Safety
    /// Unsynchronized access
    unsafe fn read_from_idx(&self, index: u32) -> RawCqe {
        let mask = *self.mask_ref();
        let cqe_ptr = self.cq_bytes_ptr().offset(self.meta.params.cq_off.cqes as isize) as *const RawCqe;

        let cqe_idx = index & mask;
        cqe_ptr.offset(cqe_idx as isize).read()
    }
}

impl IoUringCqInner {
    fn dequeue(&self) -> Option<RawCqe> {
        let head = self.head_ref();
        let tail = self.tail_ref();

        let index = head.load(Ordering::Acquire);
        let tail = tail.load(Ordering::Acquire);
        if index == tail {
            return None;
        }
        head.fetch_add(1, Ordering::Release);

        let cqe = unsafe { self.read_from_idx(index) };
        self.meta.pending.fetch_sub(1, Ordering::Relaxed);
        Some(cqe)
    }
}

// No unsynchronized access of raw pointers
unsafe impl Send for IoUring {}

#[derive(Debug)]
pub enum Error {
    MapFailed(i32),
    SubmissionQueueFull,
    SubmissionFailed(i32),
    Other(i32),
}

impl IoUring {
    /// `entries` 개의 SQE를 가질 수 있는 io_uring 구조체를 만듭니다.
    pub fn new(entries: u32) -> Result<Self, Error> {
        let meta = unsafe {
            // 커널에 링 버퍼를 부탁한다. 커널은 버퍼를 만든 뒤 관련 파라미터를 돌려준다.
            let mut params =
                std::mem::MaybeUninit::<sys::io_uring_params>::zeroed().assume_init();
            let fd = io_uring_setup(entries, &mut params);
            if fd == -1 {
                let errno = errno::errno();
                return Err(Error::Other(errno));
            }

            IoUringMeta::new(fd, params)
        };
        let meta = Arc::new(meta);
        let fd = meta.fd;
        let params = &meta.params;

        // Linux >=5.4에서는 mmap 한 번에 SQ와 CQ가 모두 매핑되어, 쓸 때는 SQ에 쓰고 읽을 때는 CQ를
        // 읽게 된다. features 필드의 IORING_FEAT_SINGLE_MMAP 비트를 확인해 만약 그렇다면 두 개의
        // 큐 중에 큰 쪽으로 한 번만 mmap한다.
        let is_single_mmap = params.features & sys::IORING_FEAT_SINGLE_MMAP != 0;
        let sizes = meta.map_sizes();

        let mut sq = IoUringSqInner {
            meta: meta.clone(),
            sq_raw: std::ptr::null_mut(),
            sqe_raw: std::ptr::null_mut(),
            updating_tail: AtomicU32::new(0),
        };
        sq.sq_raw = unsafe {
            let map_result = mman::mmap(
                std::ptr::null_mut(),
                sizes.sq,
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED | mman::MapFlags::MAP_POPULATE,
                fd,
                sys::IORING_OFF_SQ_RING as i64,
            );
            match map_result {
                Ok(sq_raw) => sq_raw,
                Err(errno) => return Err(Error::MapFailed(errno as i32)),
            }
        };
        sq.updating_tail.store(sq.tail_ref().load(Ordering::Acquire), Ordering::Release);

        let mut cq = IoUringCqInner {
            meta: meta.clone(),
            cq_raw: std::ptr::null_mut(),
        };
        cq.cq_raw = if is_single_mmap {
            // SQ와 CQ가 같은 주소를 공유
            sq.sq_raw
        } else {
            // CQ를 따로 매핑해야 함
            unsafe {
                let map_result = mman::mmap(
                    std::ptr::null_mut(),
                    sizes.cq,
                    mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                    mman::MapFlags::MAP_SHARED | mman::MapFlags::MAP_POPULATE,
                    fd,
                    sys::IORING_OFF_CQ_RING as i64,
                );
                match map_result {
                    Ok(cq_raw) => cq_raw,
                    Err(errno) => return Err(Error::MapFailed(errno as i32)),
                }
            }
        };

        // 실제 SQE가 들어갈 버퍼를 매핑한다.
        sq.sqe_raw = unsafe {
            let map_result = mman::mmap(
                std::ptr::null_mut(),
                sizes.sqe,
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED | mman::MapFlags::MAP_POPULATE,
                fd,
                sys::IORING_OFF_SQES as i64,
            );
            match map_result {
                Ok(sqe_raw) => sqe_raw,
                Err(errno) => return Err(Error::MapFailed(errno as i32)),
            }
        };

        Ok(Self {
            meta,
            sq: sq.into(),
            cq: cq.into(),
        })
    }

    pub fn split(self) -> (IoUringSq, IoUringCq) {
        (self.sq, self.cq)
    }
}
