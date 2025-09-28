use super::{Context, IdleManager, IdleManagerOptions};
use futures::{
    StreamExt,
    channel::{mpsc, oneshot},
    executor::block_on,
    future::FutureExt,
    pin_mut, select,
};
use futures_timer::Delay;
use parking_lot::Mutex;
use rdev::{Event, listen};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct NativeHandler {
    receiver: mpsc::Receiver<()>,
    callbacks: Arc<Mutex<Vec<super::Callback>>>,
    idle_timeout: Duration,
    last_activity: Arc<Mutex<Instant>>,
    running: Arc<AtomicBool>,
    drop_receiver: oneshot::Receiver<()>,
}

impl NativeHandler {
    fn new(
        receiver: mpsc::Receiver<()>,
        callbacks: Arc<Mutex<Vec<super::Callback>>>,
        idle_timeout: u32,
        last_activity: Arc<Mutex<Instant>>,
        running: Arc<AtomicBool>,
        drop_receiver: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            receiver,
            callbacks,
            idle_timeout: Duration::from_millis(idle_timeout as u64),
            last_activity,
            running,
            drop_receiver,
        }
    }

    async fn run(&mut self) {
        loop {
            let sleep_fut = Delay::new(self.idle_timeout).fuse();
            let recv_fut = self.receiver.next().fuse();
            let drop_fut = (&mut self.drop_receiver).fuse();

            pin_mut!(sleep_fut, recv_fut, drop_fut);

            select! {
                _ = sleep_fut => {
                    if self.last_activity.lock().elapsed() >= self.idle_timeout {
                        self.handle_timeout();
                        break;
                    } else {
                        // Spurious wakeup, loop again to recalculate sleep time
                        continue;
                    }
                },
                event = recv_fut => {
                    if event.is_some() {
                        *self.last_activity.lock() = Instant::now();
                    }
                },
                _ = drop_fut => {
                    // Manager dropped
                    break;
                },
            }
        }
    }

    fn handle_timeout(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            for callback in self.callbacks.lock().iter_mut() {
                (callback)();
            }
            self.running.store(false, Ordering::SeqCst);
        }
    }
}

impl std::fmt::Debug for IdleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleManager")
            .field("idle_timeout", &self.idle_timeout)
            .field("callbacks", &{ self.context.lock().callbacks.lock().len() })
            .finish()
    }
}

impl Drop for IdleManager {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl IdleManager {
    /// Constructs a new [`IdleManager`] with the given options.
    pub(super) fn new_native(options: Option<IdleManagerOptions>) -> Self {
        let callbacks = options
            .as_ref()
            .map(|options| options.on_idle.clone())
            .unwrap_or_else(|| Arc::new(Mutex::new(Vec::new())));

        let idle_timeout = options
            .as_ref()
            .and_then(|options| options.idle_timeout)
            .unwrap_or(Self::DEFAULT_IDLE_TIMEOUT);

        let (event_sender, event_receiver) = mpsc::channel(100);
        let (drop_sender, drop_receiver) = oneshot::channel();

        let running = Arc::new(AtomicBool::new(true));
        let last_activity = Arc::new(Mutex::new(Instant::now()));

        let mut handler = NativeHandler::new(
            event_receiver,
            callbacks.clone(),
            idle_timeout,
            last_activity.clone(),
            running.clone(),
            drop_receiver,
        );

        thread::spawn(move || {
            block_on(handler.run());
        });

        let sender_clone = event_sender.clone();
        let running_clone = running.clone();
        thread::spawn(move || {
            let callback = move |_: Event| {
                if !running_clone.load(Ordering::SeqCst) {
                    return;
                }
                let mut sender = sender_clone.clone();
                let _ = sender.try_send(());
            };
            if let Err(error) = listen(callback) {
                eprintln!("Error listening to events: {:?}", error);
            }
        });

        // TODO: The struct definition for `IdleManager` needs to be updated.
        // The fields `_timeout_receiver` and `timeout_sender` should be replaced
        // with a single field, for example: `_drop_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>`
        Self {
            context: Arc::new(Mutex::new(Context { callbacks })),
            idle_timeout,
            running,
            event_sender: Arc::new(Mutex::new(event_sender)),
            _drop_sender: Arc::new(Mutex::new(drop_sender)),
        }
    }

    /// Exits the idle state, cancels any timeouts, removes event listeners, and executes all registered callbacks.
    pub(super) fn exit_native(&mut self) {
        if self.running.swap(false, Ordering::SeqCst) {
            for callback in self.context.lock().callbacks.lock().iter_mut() {
                (callback)();
            }
        }
    }

    /// Resets the idle timer, cancelling any existing timeout and setting a new one.
    pub(super) fn reset_timer_native(&self) {
        let _ = self.event_sender.lock().try_send(());
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_idle_manager() {
        let options = IdleManagerOptions::builder().idle_timeout(500).build();
        let idle_manager = IdleManager::new(Some(options));

        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = callback_triggered.clone();
        idle_manager.register_callback(move || {
            callback_triggered_clone.store(true, Ordering::SeqCst);
        });

        assert!(!callback_triggered.load(Ordering::SeqCst));

        // Wait for the idle timeout to trigger
        thread::sleep(Duration::from_millis(1000));

        assert!(callback_triggered.load(Ordering::SeqCst));
    }

    #[test]
    fn test_idle_manager_with_reset_timer() {
        let options = IdleManagerOptions::builder().idle_timeout(1000).build();
        let idle_manager = IdleManager::new(Some(options));

        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = callback_triggered.clone();
        idle_manager.register_callback(move || {
            callback_triggered_clone.store(true, Ordering::SeqCst);
        });

        assert!(!callback_triggered.load(Ordering::SeqCst));

        thread::sleep(Duration::from_millis(500));

        // Reset timer
        idle_manager.reset_timer();

        thread::sleep(Duration::from_millis(700));

        assert!(!callback_triggered.load(Ordering::SeqCst));

        // Wait for the idle timeout to trigger
        thread::sleep(Duration::from_millis(500));

        assert!(callback_triggered.load(Ordering::SeqCst));
    }

    #[test]
    fn test_exit() {
        let options = IdleManagerOptions::builder().idle_timeout(1000).build();
        let mut idle_manager = IdleManager::new(Some(options));

        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = callback_triggered.clone();
        idle_manager.register_callback(move || {
            callback_triggered_clone.store(true, Ordering::SeqCst);
        });

        assert!(!callback_triggered.load(Ordering::SeqCst));

        thread::sleep(Duration::from_millis(500));

        idle_manager.exit();

        assert!(callback_triggered.load(Ordering::SeqCst));

        // check that it doesn't trigger again
        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = callback_triggered.clone();
        idle_manager.register_callback(move || {
            callback_triggered_clone.store(true, Ordering::SeqCst);
        });
        thread::sleep(Duration::from_millis(1500));
        assert!(!callback_triggered.load(Ordering::SeqCst));
    }
}
