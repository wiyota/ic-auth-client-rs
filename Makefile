build-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target web

test-chrome:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --chrome

test-firefox:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --firefox

test-safari:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --safari

doc:
	RUSTDOCFLAGS='--cfg docsrs' cargo +nightly doc --all-features --no-deps --open

clean:
	rm -rf target
	rm -rf pkg
	cargo clean
