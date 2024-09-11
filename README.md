# ic-auth-client-rs

Port of [@dfinity/auth-client](https://github.com/dfinity/agent-js/tree/main/packages/auth-client) for the Rust programming language.

### In the browser:

```rust
use ic_auth_client::AuthClient;
```

To get started with auth client, run

```rust
let mut auth_client = AuthClient::builder()
    // any configurations
    .build()
    .await;
```

The auth_client can log in with

```rust
use ic_auth_client::AuthClientLoginOptions;

let options = AuthClientLoginOptions::builder()
    .max_time_to_live(7 * 24 * 60 * 60 * 1000 * 1000 * 1000)
    .on_success(|auth_success| {
        // handle success
    })
    .build();

auth_client.login_with_options(options);
```

It opens an `identity.ic0.app` window, saves your delegation to localStorage, and then sets you up with an identity.

Then, you can use that identity to make authenticated calls using the `ic-agent::Agent`.

```rust
let identity = auth_client.identity();

let agent = Agent::builder()
    .with_url(url)
    .with_identity(identity)
    .build()?;
```
