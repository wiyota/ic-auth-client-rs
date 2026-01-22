candid:
	cargo build -p backend --release --target wasm32-unknown-unknown
	candid-extractor target/wasm32-unknown-unknown/release/backend.wasm > .candid/backend.did

tailwind-build:
	cd crates/frontend && npm run tailwind:build

tailwind-watch:
	cd crates/frontend && npm run tailwind:watch

build-frontend: tailwind-build
	dx build --platform web --release -p frontend

build-backend:
	cargo build -p backend --release --target wasm32-unknown-unknown

deploy:
	dfx deps pull
	dfx deps init --argument '(null)' internet-identity
	dfx deps deploy
	dfx deploy

deploy-ic:
	dfx deploy --ic

clean:
	rm -rf .dfx
	rm -rf crates/frontend/dist
	rm -rf target
	rm -f .env
	cargo clean
