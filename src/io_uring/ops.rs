use std::os::unix::prelude::*;

use super::sys::{
    self,
    io_uring_cqe as RawCqe,
    io_uring_sqe as RawSqe,
};

pub trait SubmissionOp: Sized {
    type Context: Send + 'static;
    type Result: Send;

    unsafe fn from_cqe(cqe: RawCqe) -> Self::Result;
    fn into_sqe(self) -> (RawSqe, CompletionReceiver<Self>);
}

pub(crate) struct CompletionSender {
    pub(crate) channel: crossbeam_channel::Sender<RawCqe>,
    pub(crate) ctx: Box<dyn std::any::Any + Send>,
}

pub struct CompletionReceiver<Op> {
    channel: crossbeam_channel::Receiver<RawCqe>,
    _marker: std::marker::PhantomData<Op>,
}

impl<Op: SubmissionOp> CompletionReceiver<Op> {
    pub fn recv(self) -> Op::Result {
        let cqe = self.channel.recv()
            .expect("channel disconnected");
        unsafe { Op::from_cqe(cqe) }
    }

    pub fn try_recv(self) -> Result<Op::Result, Self> {
        self.channel.try_recv()
            .map_err(|_| self)
            .map(|cqe| unsafe { Op::from_cqe(cqe) })
    }
}

fn completion_channel<Op: SubmissionOp>(ctx: Op::Context) -> (CompletionSender, CompletionReceiver<Op>) {
    let (tx, rx) = crossbeam_channel::bounded(1);
    let sender = CompletionSender {
        channel: tx,
        ctx: Box::new(ctx),
    };
    let receiver = CompletionReceiver {
        channel: rx,
        _marker: Default::default(),
    };
    (sender, receiver)
}

pub struct VectoredRead<Fd> {
    fd: Fd,
    offset: u64,
    iovec: Vec<Vec<u8>>,
    flags: sys::__kernel_rwf_t,
}

impl<Fd> VectoredRead<Fd> {
    pub fn new(fd: Fd, offset: u64, iovec: Vec<Vec<u8>>) -> Self {
        Self {
            fd,
            offset,
            iovec,
            flags: 0,
        }
    }

    pub fn with_single_buffer(fd: Fd, offset: u64, buf: Vec<u8>) -> Self {
        Self::new(fd, offset, vec![buf])
    }
}

pub struct VectoredReadCtx<Fd> {
    fd: Fd,
    iovec_sys: Box<[libc::iovec]>,
    iovec_caps: Box<[usize]>,
}

// SAFETY: iovec data is from Vec<u8>, which is Send + Sync
unsafe impl<Fd: Send> Send for VectoredReadCtx<Fd> {}
unsafe impl<Fd: Sync> Sync for VectoredReadCtx<Fd> {}

pub struct VectoredReadResult<Fd> {
    pub fd: Fd,
    pub iovec: Vec<Vec<u8>>,
    pub result: Result<usize, std::io::Error>,
}

impl<Fd: AsRawFd + Send + 'static> SubmissionOp for VectoredRead<Fd> {
    type Context = VectoredReadCtx<Fd>;
    type Result = VectoredReadResult<Fd>;

    unsafe fn from_cqe(cqe: RawCqe) -> Self::Result {
        let sender = cqe.user_data as *mut CompletionSender;
        let sender = Box::from_raw(sender);
        let ctx = Box::<dyn std::any::Any + Send>::downcast::<Self::Context>(sender.ctx)
            .expect("wrong context");
        let iovec = ctx.iovec_sys.iter()
            .zip(ctx.iovec_caps.iter())
            .map(|(iov, &cap)| Vec::from_raw_parts(iov.iov_base as *mut u8, iov.iov_len as usize, cap))
            .collect::<Vec<_>>();
        let res = cqe.res;
        let result = if res < 0 {
            Err(std::io::Error::from_raw_os_error(-res))
        } else {
            Ok(res as usize)
        };
        VectoredReadResult {
            fd: ctx.fd,
            iovec,
            result,
        }
    }

    fn into_sqe(self) -> (RawSqe, CompletionReceiver<Self>) {
        let (iovec_sys, iovec_caps) = self
            .iovec
            .into_iter()
            .map(|mut v| {
                let iovec = libc::iovec { iov_base: v.as_mut_ptr() as *mut _, iov_len: v.len() };
                let cap = v.capacity();
                std::mem::forget(v);
                (iovec, cap)
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let iovec_sys = iovec_sys.into_boxed_slice();
        let iovec_caps = iovec_caps.into_boxed_slice();

        let ctx = VectoredReadCtx {
            fd: self.fd,
            iovec_sys,
            iovec_caps,
        };
        let rawfd = ctx.fd.as_raw_fd();
        let iovec_sys_ptr = ctx.iovec_sys.as_ptr();
        let iovec_sys_len = ctx.iovec_sys.len();

        let (tx, rx) = completion_channel(ctx);
        let tx = Box::new(tx);

        let sqe = RawSqe {
            opcode: sys::IORING_OP_READV as u8,
            flags: 0,
            ioprio: 0,
            fd: rawfd,
            __bindgen_anon_1: sys::io_uring_sqe__bindgen_ty_1 {
                off: self.offset,
            },
            __bindgen_anon_2: sys::io_uring_sqe__bindgen_ty_2 {
                addr: iovec_sys_ptr as usize as u64,
            },
            len: iovec_sys_len as u32,
            __bindgen_anon_3: sys::io_uring_sqe__bindgen_ty_3 {
                rw_flags: self.flags,
            },
            user_data: Box::into_raw(tx) as usize as u64,
            ..unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
        };
        (sqe, rx)
    }
}
