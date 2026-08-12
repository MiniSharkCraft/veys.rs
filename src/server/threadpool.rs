use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

struct Worker {
    #[allow(dead_code)]
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = match receiver.lock() {
                Ok(guard) => guard.recv(),
                Err(_) => break,
            };

            match message {
                Ok(job) => {
                    let result = catch_unwind(AssertUnwindSafe(job));
                    if result.is_err() {
                        eprintln!("[ERROR] ThreadPool worker {} caught job panic", id);
                    }
                }
                Err(_) => {
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}

impl ThreadPool {
    pub fn new(size: usize) -> Result<ThreadPool, &'static str> {
        if size == 0 {
            return Err("ThreadPool size must be greater than 0");
        }

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        Ok(ThreadPool {
            workers,
            sender: Some(sender),
        })
    }

    pub fn execute<F>(&self, f: F) -> Result<(), &'static str>
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        if let Some(ref sender) = self.sender {
            sender
                .send(job)
                .map_err(|_| "Failed to send job to ThreadPool channel")
        } else {
            Err("ThreadPool is shut down")
        }
    }

    pub fn shutdown(&mut self) {
        drop(self.sender.take());

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_threadpool_reject_zero_workers() {
        let pool = ThreadPool::new(0);
        assert!(pool.is_err());
    }

    #[test]
    fn test_worker_panic_isolation() {
        let pool = ThreadPool::new(4).unwrap();
        let counter = Arc::new(AtomicUsize::new(0));

        pool.execute(|| {
            panic!("Test panic isolation");
        })
        .unwrap();

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            pool.execute(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        }

        drop(pool);

        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn test_threadpool_graceful_shutdown() {
        let mut pool = ThreadPool::new(2).unwrap();
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..5 {
            let counter_clone = Arc::clone(&counter);
            pool.execute(move || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        }

        pool.shutdown();
        assert_eq!(counter.load(Ordering::SeqCst), 5);
        assert!(pool.execute(|| {}).is_err());
    }
}
