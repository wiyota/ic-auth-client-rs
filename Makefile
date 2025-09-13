build-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --release --target wasm32-unknown-unknown

clean:
	rm -rf target
	cargo clean
