use parking_lot::Mutex;
use std::sync::Arc;

#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(target_family = "wasm")]
#[cfg(feature = "wasm-js")]
mod wasm_js;

/// A callback function to be executed when the system becomes idle.
pub type Callback = Box<dyn FnMut() + Send>;

#[derive(Default)]
pub(crate) struct Context {
    pub(crate) callbacks: Arc<Mutex<Vec<Callback>>>,
}

/// IdleManager is a struct that manages idle state and events.
/// It provides functionality to register callbacks that are triggered when the system becomes idle,
/// and to reset the idle timer when certain events occur.
#[derive(Clone)]
pub struct IdleManager {
    context: Arc<Mutex<Context>>,
    idle_timeout: u32,
    #[cfg(target_family = "wasm")]
    #[cfg(feature = "wasm-js")]
    js_sender: Arc<Mutex<futures::channel::mpsc::Sender<wasm_js::JsMessage>>>,
    #[cfg(target_family = "wasm")]
    #[cfg(feature = "wasm-js")]
    is_initialized: Arc<Mutex<bool>>,
    #[cfg(not(target_family = "wasm"))]
    running: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(not(target_family = "wasm"))]
    event_sender: Arc<Mutex<futures::channel::mpsc::Sender<()>>>,
    #[cfg(not(target_family = "wasm"))]
    _timeout_receiver: Arc<tokio::sync::watch::Receiver<()>>, // To keep the channel open
    #[cfg(not(target_family = "wasm"))]
    timeout_sender: Arc<tokio::sync::watch::Sender<()>>,
}

impl IdleManager {
    /// Default idle timeout duration in milliseconds (10 minutes).
    pub const DEFAULT_IDLE_TIMEOUT: u32 = 10 * 60 * 1000;
    /// Default scroll debounce duration in milliseconds.
    #[cfg(target_family = "wasm")]
    #[cfg(feature = "wasm-js")]
    pub const DEFAULT_SCROLL_DEBOUNCE: u32 = 100;

    /// Registers a callback to be executed when the system becomes idle.
    pub fn register_callback<F>(&self, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        self.context
            .lock()
            .callbacks
            .lock()
            .push(Box::new(callback));
    }
}

/// IdleManagerOptions is a struct that contains options for configuring an [`IdleManager`].
#[derive(Default, Clone, bon::Builder)]
pub struct IdleManagerOptions {
    /// Callback functions to be executed when the system becomes idle.
    #[builder(field)]
    pub on_idle: Arc<Mutex<Vec<Callback>>>,
    /// The duration of inactivity after which the system is considered idle in milliseconds.
    pub idle_timeout: Option<u32>,
    /// A flag indicating whether to capture scroll events.
    pub capture_scroll: Option<bool>,
    /// A delay for debouncing scroll events in milliseconds.
    pub scroll_debounce: Option<u32>,
}

impl std::fmt::Debug for IdleManagerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let callback_count = self.on_idle.lock().len();
        f.debug_struct("IdleManagerOptions")
            .field("on_idle", &format!("{} callbacks", callback_count))
            .field("idle_timeout", &self.idle_timeout)
            .field("capture_scroll", &self.capture_scroll)
            .field("scroll_debounce", &self.scroll_debounce)
            .finish()
    }
}

#[allow(dead_code)]
impl<S: idle_manager_options_builder::State> IdleManagerOptionsBuilder<S> {
    /// Sets a callback to be executed when the system becomes idle.
    ///
    /// It is possible to set multiple callbacks.
    pub fn on_idle(self, value: fn()) -> Self {
        self.on_idle
            .lock()
            .push(Box::new(value) as Box<dyn FnMut() + Send>);
        self
    }
}
