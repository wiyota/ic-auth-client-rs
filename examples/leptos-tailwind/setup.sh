#!/usr/bin/env bash

# make the target directory/file before build if not exist
path='dist/frontend'
if [ ! -d $path ]; then
    mkdir $path
fi
path='crates/frontend/style/tw_output.css'
if [ ! -f $path ]; then
    touch $path
fi

# npm install
npm ci

# build user-canister
cargo build -p ic_auth_client_leptos_user_canister --release --target wasm32-unknown-unknown

# pull and setup internet identity canister in local
dfx deps pull
dfx deps init --argument '(null)' internet-identity

# create backend canister in local
dfx canister create ic-auth-client-leptos-backend

# deploy canisters in local
dfx deps deploy
dfx deploy --with-cycles 5000000000000 ic-auth-client-leptos-backend
