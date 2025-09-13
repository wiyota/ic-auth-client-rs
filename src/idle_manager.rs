use futures::channel::{mpsc, oneshot};
use gloo_utils::window;
use std::{
    mem,
    sync::{Arc, Mutex},
};
use wasm_bindgen::{closure::Closure, prelude::*};
use wasm_bindgen_futures::spawn_local;
use web_sys::{Event, Window};

type Callback = Box<dyn FnMut() + Send>;
type JsCallback = Closure<dyn FnMut(Event)>;

const EVENTS: [&str; 6] = [
    "load",
    "mousedown",
    "mousemove",
    "keydown",
    "touchstart",
    "wheel",
];

/// The relevant state of JavaScript
struct JsContext {
    event_handlers: Vec<(String, JsCallback)>,
    window: Window,
}

impl JsContext {
    fn new() -> Self {
        Self {
            event_handlers: Vec::new(),
            window: window(),
        }
    }

    fn add_event_listener(&mut self, event_type: &str, callback: JsCallback) {
        self.window
            .add_event_listener_with_callback(event_type, callback.as_ref().unchecked_ref())
            .expect("should add event listener");
        self.event_handlers.push((event_type.to_string(), callback));
    }

    fn remove_all_listeners(&mut self) {
        for (event_type, handler) in self.event_handlers.drain(..) {
            self.window
                .remove_event_listener_with_callback(&event_type, handler.as_ref().unchecked_ref())
                .expect("should remove event listener");
        }
    }

    fn clear_timeout(&self, timeout_id: i32) {
        self.window.clear_timeout_with_handle(timeout_id);
    }

    fn set_timeout(&self, closure: &Closure<dyn FnMut()>, timeout: i32) -> Result<i32, JsValue> {
        self.window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                timeout,
            )
    }
}

impl Drop for JsContext {
    fn drop(&mut self) {
        self.remove_all_listeners();
    }
}

// Context contains only states that can be shared among threads
#[derive(Default)]
struct Context {
    callbacks: Arc<Mutex<Vec<Callback>>>,
}

enum JsMessage {
    ResetTimer(u32),
    Cleanup,
    ScrollDebounce(u32),
}

struct JsHandler {
    context: JsContext,
    receiver: mpsc::Receiver<JsMessage>,
    sender: mpsc::Sender<JsMessage>,
    current_timer: Option<i32>,
    current_scroll_debounce_timer: Option<i32>,
    exit_closure: Option<Closure<dyn FnMut()>>,
    reset_closure: Option<Closure<dyn FnMut()>>,
}

impl JsHandler {
    fn new(receiver: mpsc::Receiver<JsMessage>, sender: mpsc::Sender<JsMessage>) -> Self {
        Self {
            context: JsContext::new(),
            receiver,
            sender,
            current_timer: None,
            current_scroll_debounce_timer: None,
            exit_closure: None,
            reset_closure: None,
        }
    }

    fn get_handler_sender(&self) -> mpsc::Sender<JsMessage> {
        self.sender.clone()
    }

    async fn run(&mut self) {
        use futures::StreamExt;
        while let Some(msg) = self.receiver.next().await {
            match msg {
                JsMessage::ResetTimer(timeout) => self.handle_reset_timer(timeout),
                JsMessage::Cleanup => self.handle_cleanup(),
                JsMessage::ScrollDebounce(delay) => self.handle_scroll_debounce(delay),
            }
        }
    }

    fn handle_reset_timer(&mut self, timeout: u32) {
        // Clear existing timeout if it exists
        if let Some(timer_id) = self.current_timer.take() {
            self.context.clear_timeout(timer_id);
        }

        // If timeout is 0, just reset the timer without setting a new one
        if timeout == 0 {
            return;
        }

        // Create a sender for the IdleManager to send the Cleanup message
        let (sender, oneshot_receiver) = oneshot::channel();

        // Use a closure to handle the timeout
        let exit_closure = Closure::once(move || {
            // Send a message that will be received by the oneshot_receiver
            let _ = sender.send(());
        });

        // Set the timeout with the closure
        match self.context.set_timeout(&exit_closure, timeout as i32) {
            Ok(timer_id) => {
                self.current_timer = Some(timer_id);
                self.exit_closure = Some(exit_closure);

                // Spawn a task to handle the oneshot receiver
                let mut sender = self.get_handler_sender();
                spawn_local(async move {
                    // Wait for the oneshot message
                    if oneshot_receiver.await.is_ok() {
                        // Then send the cleanup message to the handler
                        use futures::SinkExt;
                        let _ = sender.send(JsMessage::Cleanup).await;
                    }
                });
            }
            Err(_) => {
                // If setting timeout fails, drop the closure
                drop(exit_closure);
            }
        }
    }

    fn handle_cleanup(&mut self) {
        // Clear existing timeouts
        if let Some(timer_id) = self.current_timer.take() {
            self.context.clear_timeout(timer_id);
        }

        if let Some(timer_id) = self.current_scroll_debounce_timer.take() {
            self.context.clear_timeout(timer_id);
        }

        // Remove all event listeners
        self.context.remove_all_listeners();

        // Drop closures
        self.exit_closure = None;
        self.reset_closure = None;
    }

    fn handle_scroll_debounce(&mut self, delay: u32) {
        // Clear existing scroll debounce timeout if it exists
        if let Some(timer_id) = self.current_scroll_debounce_timer.take() {
            self.context.clear_timeout(timer_id);
        }

        // Create a sender for the debounce timer
        let (sender, oneshot_receiver) = oneshot::channel();

        // Use a closure to handle the timeout
        let reset_closure = Closure::once(move || {
            // Send a message that will be received by the oneshot_receiver
            let _ = sender.send(());
        });

        // Set the timeout with the closure
        match self.context.set_timeout(&reset_closure, delay as i32) {
            Ok(timer_id) => {
                self.current_scroll_debounce_timer = Some(timer_id);
                self.reset_closure = Some(reset_closure);

                // Spawn a task to handle the oneshot receiver
                let mut sender = self.get_handler_sender();
                spawn_local(async move {
                    // Wait for the oneshot message
                    if oneshot_receiver.await.is_ok() {
                        // Then send the reset timer message to the handler
                        use futures::SinkExt;
                        let _ = sender.send(JsMessage::ResetTimer(0)).await;
                    }
                });
            }
            Err(_) => {
                // If setting timeout fails, drop the closure
                drop(reset_closure);
            }
        }
    }
}

/// IdleManager is a struct that manages idle state and events.
/// It provides functionality to register callbacks that are triggered when the system becomes idle,
/// and to reset the idle timer when certain events occur.
#[derive(Clone)]
pub struct IdleManager {
    context: Arc<Mutex<Context>>,
    idle_timeout: u32,
    js_sender: Arc<Mutex<mpsc::Sender<JsMessage>>>,
    is_initialized: Arc<Mutex<bool>>,
}

impl std::fmt::Debug for IdleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleManager")
            .field("idle_timeout", &self.idle_timeout)
            .field("callbacks", &{
                if let Ok(context) = self.context.lock() {
                    if let Ok(callbacks) = context.callbacks.lock() {
                        callbacks.len()
                    } else {
                        0
                    }
                } else {
                    0
                }
            })
            .field("js_sender", &"<mpsc channel>")
            .finish()
    }
}

impl Drop for IdleManager {
    fn drop(&mut self) {
        use futures::SinkExt;
        let mut sender_clone = self.js_sender.lock().unwrap().clone();
        spawn_local(async move {
            let _ = sender_clone.send(JsMessage::Cleanup).await;
        });
    }
}

impl IdleManager {
    /// Default idle timeout duration in milliseconds (10 minutes).
    const DEFAULT_IDLE_TIMEOUT: u32 = 10 * 60 * 1000;
    /// Default scroll debounce duration in milliseconds.
    const DEFAULT_SCROLL_DEBOUNCE: u32 = 100;

    /// Constructs a new [`IdleManager`] with the given options.
    pub fn new(options: Option<IdleManagerOptions>) -> Self {
        let callbacks = options
            .as_ref()
            .map(|options| options.on_idle.clone())
            .unwrap_or_else(|| Arc::new(Mutex::new(Vec::new())));

        let idle_timeout = options
            .as_ref()
            .and_then(|options| options.idle_timeout)
            .unwrap_or(Self::DEFAULT_IDLE_TIMEOUT);

        let (sender, receiver) = mpsc::channel(10);
        let js_sender = Arc::new(Mutex::new(sender.clone()));

        // Start the JS handler in a separate task
        let handler_receiver = receiver;
        let handler_sender = sender;
        spawn_local(async move {
            let mut handler = JsHandler::new(handler_receiver, handler_sender);
            handler.run().await;
        });

        let instance = Self {
            context: Arc::new(Mutex::new(Context { callbacks })),
            idle_timeout,
            js_sender,
            is_initialized: Arc::new(Mutex::new(false)),
        };

        instance.initialize_event_listeners(&options);
        instance.reset_timer();
        instance
    }

    fn initialize_event_listeners(&self, options: &Option<IdleManagerOptions>) {
        let mut is_initialized = self.is_initialized.lock().unwrap();
        if *is_initialized {
            return;
        }

        let mut js_context = JsContext::new();

        for event_type in EVENTS.iter() {
            let sender = self.js_sender.lock().unwrap().clone();
            let callback = Closure::wrap(Box::new(move |_: Event| {
                use futures::SinkExt;
                let mut sender_clone = sender.clone();
                spawn_local(async move {
                    let _ = sender_clone.send(JsMessage::ResetTimer(0)).await;
                });
            }) as Box<dyn FnMut(Event)>);

            js_context.add_event_listener(event_type, callback);
        }

        if let Some(true) = options.as_ref().and_then(|options| options.capture_scroll) {
            let sender = self.js_sender.lock().unwrap().clone();
            let scroll_debounce = options
                .as_ref()
                .and_then(|options| options.scroll_debounce)
                .unwrap_or(Self::DEFAULT_SCROLL_DEBOUNCE);

            let callback = Closure::wrap(Box::new(move |_: Event| {
                use futures::SinkExt;
                let mut sender_clone = sender.clone();
                spawn_local(async move {
                    let _ = sender_clone
                        .send(JsMessage::ScrollDebounce(scroll_debounce))
                        .await;
                });
            }) as Box<dyn FnMut(Event)>);

            js_context.add_event_listener("scroll", callback);
        }

        *is_initialized = true;
        Box::leak(Box::new(js_context));
    }

    /// Registers a callback to be executed when the system becomes idle.
    pub fn register_callback<F>(&self, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        if let Ok(context) = self.context.lock() {
            if let Ok(mut callbacks) = context.callbacks.lock() {
                callbacks.push(Box::new(callback));
            }
        }
    }

    /// Exits the idle state, cancels any timeouts, removes event listeners, and executes all registered callbacks.
    pub fn exit(&mut self) {
        use futures::SinkExt;
        // Send cleanup message to JS handler
        let mut sender_clone = self.js_sender.lock().unwrap().clone();
        spawn_local(async move {
            let _ = sender_clone.send(JsMessage::Cleanup).await;
        });

        // Execute callbacks
        if let Ok(context) = self.context.lock() {
            if let Ok(mut callbacks) = context.callbacks.lock() {
                for callback in callbacks.iter_mut() {
                    (callback)();
                }
            }
        }
    }
    /// Resets the idle timer, cancelling any existing timeout and setting a new one.
    fn reset_timer(&self) {
        use futures::SinkExt;
        let mut sender_clone = self.js_sender.lock().unwrap().clone();
        let timeout = self.idle_timeout;
        spawn_local(async move {
            let _ = sender_clone.send(JsMessage::ResetTimer(timeout)).await;
        });
    }
}
/// IdleManagerOptions is a struct that contains options for configuring an [`IdleManager`].
#[derive(Default, Clone)]
pub struct IdleManagerOptions {
    /// A callback function to be executed when the system becomes idle.
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
        let callback_count = if let Ok(callbacks) = self.on_idle.lock() {
            callbacks.len()
        } else {
            0
        };
        f.debug_struct("IdleManagerOptions")
            .field("on_idle", &format!("{} callbacks", callback_count))
            .field("idle_timeout", &self.idle_timeout)
            .field("capture_scroll", &self.capture_scroll)
            .field("scroll_debounce", &self.scroll_debounce)
            .finish()
    }
}

impl IdleManagerOptions {
    /// Returns a new `IdleManagerOptionsBuilder` to construct an `IdleManagerOptions` struct.
    pub fn builder() -> IdleManagerOptionsBuilder {
        IdleManagerOptionsBuilder::default()
    }
}

/// Builder for the [`IdleManagerOptions`].
#[derive(Default)]
pub struct IdleManagerOptionsBuilder {
    on_idle: Vec<Callback>,
    idle_timeout: Option<u32>,
    capture_scroll: Option<bool>,
    scroll_debounce: Option<u32>,
}

impl IdleManagerOptionsBuilder {
    /// A callback function to be executed when the system becomes idle.
    pub fn on_idle(&mut self, on_idle: fn()) -> &mut Self {
        self.on_idle
            .push(Box::new(on_idle) as Box<dyn FnMut() + Send>);
        self
    }

    /// The duration of inactivity after which the system is considered idle in milliseconds.
    pub fn idle_timeout(&mut self, idle_timeout: u32) -> &mut Self {
        self.idle_timeout = Some(idle_timeout);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(&mut self, capture_scroll: bool) -> &mut Self {
        self.capture_scroll = Some(capture_scroll);
        self
    }

    /// A delay for debouncing scroll events in milliseconds.
    pub fn scroll_debounce(&mut self, scroll_debounce: u32) -> &mut Self {
        self.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// Builds the [`IdleManagerOptions`] struct.
    pub fn build(&mut self) -> IdleManagerOptions {
        IdleManagerOptions {
            on_idle: Arc::new(Mutex::new(mem::take(&mut self.on_idle))),
            idle_timeout: self.idle_timeout,
            capture_scroll: self.capture_scroll,
            scroll_debounce: self.scroll_debounce,
        }
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sleep::sleep;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_idle_manager() {
        let options = IdleManagerOptions::builder().idle_timeout(500).build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Arc::new(Mutex::new(false));
        let callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            *callback_clone.lock().unwrap() = true;
        });

        assert!(!*callback.lock().unwrap());

        // Wait for the idle timeout to trigger
        sleep(2000).await;

        assert!(*callback.lock().unwrap());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_reset_timer() {
        let options = IdleManagerOptions::builder().idle_timeout(1000).build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Arc::new(Mutex::new(false));
        let callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            *callback_clone.lock().unwrap() = true;
        });

        assert!(!*callback.lock().unwrap());

        sleep(500).await;

        // Trigger a mousemove event
        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("mousemove");
        window.dispatch_event(&event).unwrap();

        sleep(700).await;

        assert!(!*callback.lock().unwrap());

        // Wait for the idle timeout to trigger
        sleep(500).await;

        assert!(*callback.lock().unwrap());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_scroll_debounce_1() {
        let options = IdleManagerOptions::builder()
            .idle_timeout(1000)
            .capture_scroll(true)
            .scroll_debounce(500)
            .build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Arc::new(Mutex::new(false));
        let callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            *callback_clone.lock().unwrap() = true;
        });

        assert!(!*callback.lock().unwrap());

        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("scroll");

        for _ in 0..7 {
            sleep(200).await;
            window.dispatch_event(&event).unwrap();
        }

        assert!(*callback.lock().unwrap());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_scroll_debounce_2() {
        let options = IdleManagerOptions::builder()
            .idle_timeout(1000)
            .capture_scroll(true)
            .scroll_debounce(500)
            .build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Arc::new(Mutex::new(false));
        let callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            *callback_clone.lock().unwrap() = true;
        });

        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("scroll");
        window.dispatch_event(&event).unwrap();

        assert!(!*callback.lock().unwrap());

        sleep(1200).await;

        assert!(!*callback.lock().unwrap());

        sleep(700).await;

        assert!(*callback.lock().unwrap());
    }
}
