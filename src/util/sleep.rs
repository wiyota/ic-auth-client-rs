use std::time::Duration;

#[cfg(not(target_family = "wasm"))]
use std::thread::sleep as std_sleep;
#[cfg(target_family = "wasm")]
use wasm_timer::Delay;

/// Sleep for the given number of milliseconds
pub async fn sleep(ms: u64) {
    #[cfg(target_family = "wasm")]
    {
        match Delay::new(Duration::from_millis(ms)).await {
            Ok(_) => (),
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::error!("Error sleeping: {_e}");
            }
        };
    }
    #[cfg(not(target_family = "wasm"))]
    {
        std_sleep(Duration::from_millis(ms));
    }
}
