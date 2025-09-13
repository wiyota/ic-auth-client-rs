use std::time::Duration;

/// Sleep for the given number of milliseconds
pub async fn sleep(ms: u64) {
    #[cfg(target_family = "wasm")]
    {
        match wasm_timer::Delay::new(Duration::from_millis(ms)).await {
            Ok(_) => (),
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Error sleeping: {_e}");
            }
        };
    }
    #[cfg(not(target_family = "wasm"))]
    {
        std::thread::sleep(Duration::from_millis(ms));
    }
}
