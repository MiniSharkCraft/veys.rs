use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

#[allow(dead_code)]
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
    fn new(
        id: usize,
        receiver: Arc<Mutex<mpsc::Receiver<Job>>>,
        error_log: Option<Arc<String>>,
    ) -> Worker {
        let thread = thread::spawn(move || loop {
            // Lock only long enough to dequeue a job; release before executing.
            // Previously the MutexGuard was held across the blocking recv(), which
            // serialised all N workers to one: the other N-1 threads all blocked on
            // receiver.lock() while a single worker sat in recv().
            let message = {
                let guard = match receiver.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                guard.recv()
                // guard (MutexGuard) is dropped here, before executing the job.
            };

            match message {
                Ok(job) => {
                    let result = catch_unwind(AssertUnwindSafe(job));
                    if result.is_err() {
                        if let Some(destination) = error_log.as_deref() {
                            crate::server::logging::error(
                                destination,
                                &format!("ThreadPool worker {id} caught job panic"),
                            );
                        } else {
                            eprintln!("[ERROR] ThreadPool worker {} caught job panic", id);
                        }
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

#[allow(dead_code)]
impl ThreadPool {
    pub fn new(size: usize) -> Result<ThreadPool, &'static str> {
        Self::with_error_log(size, None)
    }

    pub fn new_with_error_log(size: usize, destination: &str) -> Result<ThreadPool, &'static str> {
        Self::with_error_log(size, Some(destination.to_string()))
    }

    fn with_error_log(
        size: usize,
        destination: Option<String>,
    ) -> Result<ThreadPool, &'static str> {
        if size == 0 {
            return Err("ThreadPool size must be greater than 0");
        }

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let error_log = destination.map(Arc::new);

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver), error_log.clone()));
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
    fn worker_panics_use_configured_error_log() {
        let path =
            std::env::temp_dir().join(format!("veysrs-threadpool-error-{}", std::process::id()));
        let pool = ThreadPool::new_with_error_log(1, path.to_str().unwrap()).unwrap();
        pool.execute(|| panic!("test worker panic")).unwrap();
        drop(pool);
        let output = std::fs::read_to_string(&path).unwrap();
        assert!(output.contains("caught job panic"));
        std::fs::remove_file(path).ok();
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
