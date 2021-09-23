use std::os::unix::prelude::*;

mod io_uring;
use io_uring::{
    sys as io_uring_sys,
    IoUring,
};

fn main() {
    let mut uring = IoUring::new(2).expect("Failed to request ring buffer");
    let (mut sq, mut cq) = uring.queue();

    let file = std::fs::File::open("test").unwrap();

    // preadv 명령을 담은 SQE를 초기화한다.
    let mut sqe =
        unsafe { std::mem::MaybeUninit::<io_uring::RawSqe>::zeroed().assume_init() };
    let mut buf = vec![0u8; 4096];
    let iovecs = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    sqe.opcode = io_uring_sys::IORING_OP_READV as u8; // preadv
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
