use super::{Context, IdleManager, IdleManagerOptions};
use futures::channel::{mpsc, oneshot};
use gloo_utils::window;
use parking_lot::Mutex;
use std::sync::Arc;
use wasm_bindgen::{closure::Closure, prelude::*};
use wasm_bindgen_futures::spawn_local;
use web_sys::{Event, Window};

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

pub enum JsMessage {
    ResetTimer(u32),
    Cleanup,
    CleanupWithCallbacks,
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
    callbacks: Arc<Mutex<Vec<super::Callback>>>,
    idle_timeout: u32,
}

impl JsHandler {
    fn new(
        receiver: mpsc::Receiver<JsMessage>,
        sender: mpsc::Sender<JsMessage>,
        callbacks: Arc<Mutex<Vec<super::Callback>>>,
        idle_timeout: u32,
    ) -> Self {
        Self {
            context: JsContext::new(),
            receiver,
            sender,
            current_timer: None,
            current_scroll_debounce_timer: None,
            exit_closure: None,
            reset_closure: None,
            callbacks,
            idle_timeout,
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
                JsMessage::Cleanup => self.handle_cleanup(false),
                JsMessage::CleanupWithCallbacks => self.handle_cleanup(true),
                JsMessage::ScrollDebounce(delay) => self.handle_scroll_debounce(delay),
            }
        }
    }

    fn handle_reset_timer(&mut self, timeout: u32) {
        // Clear existing timeout if it exists
        if let Some(timer_id) = self.current_timer.take() {
            self.context.clear_timeout(timer_id);
        }

        let actual_timeout = if timeout == 0 {
            self.idle_timeout // Use the manager's idle_timeout to set a new timer
        } else {
            timeout
        };

        // If actual_timeout is 0, just reset the timer without setting a new one
        if actual_timeout == 0 {
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
        match self
            .context
            .set_timeout(&exit_closure, actual_timeout as i32)
        {
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
                        let _ = sender.send(JsMessage::CleanupWithCallbacks).await;
                    }
                });
            }
            Err(_) => {
                // If setting timeout fails, drop the closure
                drop(exit_closure);
            }
        }
    }

    fn handle_cleanup(&mut self, execute: bool) {
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

        // Execute callbacks
        if execute {
            for callback in self.callbacks.lock().iter_mut() {
                (callback)();
            }
        }
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

impl std::fmt::Debug for IdleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleManager")
            .field("idle_timeout", &self.idle_timeout)
            .field("callbacks", &{ self.context.lock().callbacks.lock().len() })
            .field("js_sender", &"<mpsc channel>")
            .finish()
    }
}

impl Drop for IdleManager {
    fn drop(&mut self) {
        use futures::SinkExt;
        let mut sender_clone = self.js_sender.lock().clone();
        spawn_local(async move {
            let _ = sender_clone.send(JsMessage::Cleanup).await;
        });
    }
}

impl IdleManager {
    /// Constructs a new [`IdleManager`] with the given options.
    pub(super) fn new_wasm_js(options: Option<IdleManagerOptions>) -> Self {
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
        let callbacks_for_handler = callbacks.clone();
        let idle_timeout_for_handler = idle_timeout;
        spawn_local(async move {
            let mut handler = JsHandler::new(
                handler_receiver,
                handler_sender,
                callbacks_for_handler,
                idle_timeout_for_handler,
            );
            handler.run().await;
        });

        let instance = Self {
            context: Arc::new(Mutex::new(Context { callbacks })),
            idle_timeout,
            js_sender,
            is_initialized: Arc::new(Mutex::new(false)),
        };

        instance.initialize_event_listeners(&options);
        instance.reset_timer_wasm_js();
        instance
    }

    fn initialize_event_listeners(&self, options: &Option<IdleManagerOptions>) {
        let mut is_initialized = self.is_initialized.lock();
        if *is_initialized {
            return;
        }

        let mut js_context = JsContext::new();

        for event_type in EVENTS.iter() {
            let sender = self.js_sender.lock().clone();
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
            let sender = self.js_sender.lock().clone();
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

    /// Exits the idle state, cancels any timeouts, removes event listeners, and executes all registered callbacks.
    pub(super) fn exit_wasm_js(&mut self) {
        use futures::SinkExt;
        // Send cleanup message to JS handler
        let mut sender_clone = self.js_sender.lock().clone();
        spawn_local(async move {
            let _ = sender_clone.send(JsMessage::CleanupWithCallbacks).await;
        });

        // The callbacks will be executed by JsHandler::handle_cleanup
    }
    /// Resets the idle timer, cancelling any existing timeout and setting a new one.
    pub(super) fn reset_timer_wasm_js(&self) {
        use futures::SinkExt;
        let mut sender_clone = self.js_sender.lock().clone();
        let timeout = self.idle_timeout;
        spawn_local(async move {
            let _ = sender_clone.send(JsMessage::ResetTimer(timeout)).await;
        });
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use gloo_timers::future::sleep;
    use std::time::Duration;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_idle_manager() {
        let options = IdleManagerOptions::builder().idle_timeout(500).build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Arc::new(Mutex::new(false));
        let callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            *callback_clone.lock() = true;
        });

        assert!(!*callback.lock());

        // Wait for the idle timeout to trigger
        sleep(Duration::from_millis(2000)).await;

        assert!(*callback.lock());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_reset_timer() {
        let options = IdleManagerOptions::builder().idle_timeout(1000).build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Arc::new(Mutex::new(false));
        let callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            *callback_clone.lock() = true;
        });

        assert!(!*callback.lock());

        sleep(Duration::from_millis(500)).await;

        // Trigger a mousemove event
        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("mousemove");
        window.dispatch_event(&event).unwrap();

        sleep(Duration::from_millis(700)).await;

        assert!(!*callback.lock());

        // Wait for the idle timeout to trigger
        sleep(Duration::from_millis(500)).await;

        assert!(*callback.lock());
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
            *callback_clone.lock() = true;
        });

        assert!(!*callback.lock());

        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("scroll");

        for _ in 0..7 {
            sleep(Duration::from_millis(200)).await;
            window.dispatch_event(&event).unwrap();
        }

        assert!(*callback.lock());
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
            *callback_clone.lock() = true;
        });

        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("scroll");
        window.dispatch_event(&event).unwrap();

        assert!(!*callback.lock());

        sleep(Duration::from_millis(1200)).await;

        assert!(!*callback.lock());

        sleep(Duration::from_millis(700)).await;

        assert!(*callback.lock());
    }
}
