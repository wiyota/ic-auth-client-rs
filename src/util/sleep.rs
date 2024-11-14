use std::time::Duration;

#[cfg(target_family = "wasm")]
use wasm_timer::Delay;
#[cfg(not(target_family = "wasm"))]
use std::thread::sleep as std_sleep;

/// Sleep for the given number of milliseconds
pub async fn sleep(ms: u64) {
    #[cfg(target_family = "wasm")]
    {
        Delay::new(Duration::from_millis(ms)).await.unwrap();
    }
    #[cfg(not(target_family = "wasm"))]
    {
        std_sleep(Duration::from_millis(ms));
    }
}
