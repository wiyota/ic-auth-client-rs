use std::{borrow::BorrowMut, cell::RefCell, mem, rc::Rc};
use gloo_utils::window;
use gloo_timers::callback::Timeout;
use gloo_events::EventListener;

type Callback = Box<dyn FnMut()>;

const EVENTS: [&str; 6] = ["load", "mousedown", "mousemove", "keydown", "touchstart", "wheel"];

/// IdleManager is a struct that manages idle state and events.
/// It provides functionality to register callbacks that are triggered when the system becomes idle,
/// and to reset the idle timer when certain events occur.
#[derive(Clone)]
pub struct IdleManager {
    /// A list of callbacks to be executed when the system becomes idle.
    callbacks: Rc<RefCell<Vec<Callback>>>,
    /// The duration of inactivity after which the system is considered idle.
    idle_timeout: u32,
    /// A timeout that is set to trigger the idle state.
    timeout: Rc<RefCell<Option<Timeout>>>,
    /// A timeout that is set to debounce scroll events.
    scroll_debounce_timeout: Rc<RefCell<Option<Timeout>>>,
    /// A list of event listeners that are used to reset the idle timer.
    event_handlers: Rc<RefCell<Vec<EventListener>>>,
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
            .and_then(|options| options.on_idle.clone().borrow_mut().take())
            .map_or_else(Vec::new, |callback| vec![callback]);

        let idle_timeout = options
            .as_ref()
            .and_then(|options| options.idle_timeout)
            .unwrap_or(Self::DEFAULT_IDLE_TIMEOUT);

        let mut instance = Self {
            callbacks: Rc::new(RefCell::new(callbacks)),
            idle_timeout,
            timeout: Rc::new(RefCell::new(None)),
            scroll_debounce_timeout: Rc::new(RefCell::new(None)),
            event_handlers: Rc::new(RefCell::new(Vec::new())),
        };

        EVENTS.iter().for_each(|event| {
            let mut instance_clone = instance.clone();
            let listener = EventListener::new(&window(), *event, move |_| instance_clone.reset_timer());
            instance.event_handlers.as_ref().borrow_mut().push(listener);
        });

        if let Some(true) = options.as_ref().and_then(|options| options.capture_scroll) {
            let mut instance_clone = instance.clone();
            let listener = EventListener::new(&window(), "scroll", move |_| instance_clone.scroll_debounce(&options));
            instance.event_handlers.as_ref().borrow_mut().push(listener);
        }

        instance.reset_timer();

        instance
    }

    /// Registers a callback to be executed when the system becomes idle.
    pub fn register_callback<F>(&self, callback: F)
    where
        F: FnMut() + 'static,
    {
        self.callbacks.as_ref().borrow_mut().push(Box::new(callback));
    }

    /// Exits the idle state, cancels any timeouts, removes event listeners, and executes all registered callbacks.
    pub fn exit(&mut self) {
        if let Some(timeout) = self.timeout.borrow_mut().take() {
            timeout.cancel();
        }

        self.event_handlers.as_ref().borrow_mut().clear();

        let mut callbacks = self.callbacks.as_ref().borrow_mut();
        for callback in callbacks.iter_mut() {
            (callback)();
        }
    }

    /// Resets the idle timer, cancelling any existing timeout and setting a new one.
    fn reset_timer(&mut self) {
        if let Some(timeout) = self.timeout.borrow_mut().take() {
            timeout.cancel();
        }

        let mut self_clone = self.clone();
        self.timeout.borrow_mut().replace(
            Some(Timeout::new(
                self.idle_timeout,
                move || self_clone.exit()
            ))
        );
    }

    /// Debounces scroll events, cancelling any existing timeout and setting a new one.
    ///
    /// # Arguments
    ///
    /// * `options` - An optional `IdleManagerOptions` struct that can be used to configure the debounce delay.
    fn scroll_debounce(&mut self, options: &Option<IdleManagerOptions>) {
        let delay = options
                    .as_ref()
                    .and_then(|options| options.scroll_debounce)
                    .unwrap_or(Self::DEFAULT_SCROLL_DEBOUNCE);

        let mut self_clone = self.clone();
        if let Some(timeout) = self.scroll_debounce_timeout.borrow_mut().replace(
            Some(Timeout::new(
                delay,
                move || self_clone.reset_timer()
            ))
        ) {
            timeout.cancel();
        };
    }
}

/// IdleManagerOptions is a struct that contains options for configuring an [`IdleManager`].
#[derive(Default, Clone)]
pub struct IdleManagerOptions {
    /// A callback function to be executed when the system becomes idle.
    pub on_idle: Rc<RefCell<Option<Callback>>>,
    /// The duration of inactivity after which the system is considered idle.
    pub idle_timeout: Option<u32>,
    /// A flag indicating whether to capture scroll events.
    pub capture_scroll: Option<bool>,
    /// A delay for debouncing scroll events.
    pub scroll_debounce: Option<u32>,
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
    on_idle: Option<Callback>,
    idle_timeout: Option<u32>,
    capture_scroll: Option<bool>,
    scroll_debounce: Option<u32>,
}

impl IdleManagerOptionsBuilder {
    /// A callback function to be executed when the system becomes idle.
    pub fn on_idle(&mut self, on_idle: fn()) -> &mut Self {
        self.on_idle = Some(Box::new(on_idle) as Box<dyn FnMut()>);
        self
    }

    /// The duration of inactivity after which the system is considered idle.
    pub fn idle_timeout(&mut self, idle_timeout: u32) -> &mut Self {
        self.idle_timeout = Some(idle_timeout);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(&mut self, capture_scroll: bool) -> &mut Self {
        self.capture_scroll = Some(capture_scroll);
        self
    }

    /// A delay for debouncing scroll events.
    pub fn scroll_debounce(&mut self, scroll_debounce: u32) -> &mut Self {
        self.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// Builds the [`IdleManagerOptions`] struct.
    pub fn build(&mut self) -> IdleManagerOptions {
        IdleManagerOptions {
            on_idle: Rc::new(RefCell::new(mem::take(&mut self.on_idle))),
            idle_timeout: self.idle_timeout,
            capture_scroll: self.capture_scroll,
            scroll_debounce: self.scroll_debounce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    use crate::util::sleep::sleep;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_idle_manager() {
        let options = IdleManagerOptions::builder()
            .idle_timeout(500)
            .build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Rc::new(RefCell::new(false));
        let mut callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            callback_clone.borrow_mut().replace(true);
        });

        assert!(!*callback.borrow());

        // Wait for the idle timeout to trigger
        sleep(2000).await;

        assert!(*callback.borrow());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_reset_timer() {
        let options = IdleManagerOptions::builder()
            .idle_timeout(1000)
            .build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Rc::new(RefCell::new(false));
        let mut callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            callback_clone.borrow_mut().replace(true);
        });

        assert!(!*callback.borrow());

        sleep(500).await;

        // Trigger a mousemove event
        let window = web_sys::window().unwrap();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("mousemove");
        window.dispatch_event(&event).unwrap();

        sleep(700).await;

        assert!(!*callback.borrow());

        // Wait for the idle timeout to trigger
        sleep(500).await;

        assert!(*callback.borrow());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_scroll_debounce_1() {
        let options = IdleManagerOptions::builder()
            .idle_timeout(1000)
            .capture_scroll(true)
            .scroll_debounce(500)
            .build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Rc::new(RefCell::new(false));
        let mut callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            callback_clone.borrow_mut().replace(true);
        });

        assert!(!*callback.borrow());

        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("scroll");

        for _ in 0..7 {
            sleep(200).await;
            window.dispatch_event(&event).unwrap();
        }

        assert!(*callback.borrow());
    }

    #[wasm_bindgen_test]
    async fn test_idle_manager_with_scroll_debounce_2() {
        let options = IdleManagerOptions::builder()
            .idle_timeout(1000)
            .capture_scroll(true)
            .scroll_debounce(500)
            .build();

        let idle_manager = IdleManager::new(Some(options));

        let callback = Rc::new(RefCell::new(false));
        let mut callback_clone = callback.clone();
        idle_manager.register_callback(move || {
            callback_clone.borrow_mut().replace(true);
        });

        let window = window();
        let event = window.document().unwrap().create_event("Event").unwrap();
        event.init_event("scroll");
        window.dispatch_event(&event).unwrap();

        assert!(!*callback.borrow());

        sleep(1200).await;

        assert!(!*callback.borrow());

        sleep(700).await;

        assert!(*callback.borrow());
    }
}
