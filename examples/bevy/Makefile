candid:
	cargo build -p backend --release --target wasm32-unknown-unknown
	candid-extractor target/wasm32-unknown-unknown/release/backend.wasm > .candid/backend.did

deploy:
	dfx deps pull
	dfx deps init --argument '(null)' internet-identity
	dfx deps deploy
	dfx deploy
