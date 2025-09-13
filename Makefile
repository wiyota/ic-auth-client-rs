build-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target web

test-chrome:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --chrome --headless

test-firefox:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --firefox --headless

test-safari:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --safari --headless

clean:
	rm -rf target
	rm -rf pkg
	cargo clean
