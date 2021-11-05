pub mod io_uring;
use io_uring::IoUring;

fn main() {
    let uring = IoUring::new(2).expect("Failed to request ring buffer");
    let (sq, cq) = uring.split();

    let file = std::fs::File::open("test").unwrap();
    let buf1 = vec![0u8; 4096];
    let buf2 = vec![0u8; 4096];

    /*
    let thread_handle = std::thread::spawn(move || {
        cq.run()
    });
    */

    let handle1 = sq.enqueue(io_uring::VectoredRead::with_single_buffer(file.try_clone().unwrap(), 0, buf1)).unwrap();
    let handle2 = sq.enqueue(io_uring::VectoredRead::with_single_buffer(file, 3, buf2)).unwrap();
    let submitted_count = sq.submit_all().unwrap();
    eprintln!("Submitted {} request(s)", submitted_count);
    // drop(sq);
    cq.wait();

    let mut result = handle1.recv();
    let read_cnt = result.result.unwrap();
    let buf = result.iovec.pop().unwrap();
    let data = &buf[..read_cnt];
    eprintln!("Read {} byte(s)", read_cnt);
    dbg!(data);

    let mut result = handle2.recv();
    let read_cnt = result.result.unwrap();
    let buf = result.iovec.pop().unwrap();
    let data = &buf[..read_cnt];
    eprintln!("Read {} byte(s)", read_cnt);
    dbg!(data);

    /*
    eprintln!("Joining...");
    thread_handle.join().unwrap();
    */
}
