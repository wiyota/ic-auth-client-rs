# ic-auth-client

Port of [@dfinity/auth-client](https://www.npmjs.com/package/@dfinity/auth-client) for the Rust programming language.

This is a crate for developers who build the frontend of applications for Internet Computer using Rust as the primary language.

If you use JavaScript for frontend, you can use the Internet Identity Service compatible libraries such as [@dfinity/auth-client](https://www.npmjs.com/package/@dfinity/auth-client) or [@nfid/identitykit](https://www.npmjs.com/package/@nfid/identitykit).

## Version compatibility for `ic-agent`

The table below shows the compatible versions of `ic-auth-client` for `ic-agent` versions.

| `ic-agent` version | `ic-auth-client` version |
| ------------------ | ------------------------ |
| 0.44.\*            | 0.4.\*                   |
| 0.39.\*            | 0.3.\*                   |
| 0.37.\* or 0.38.\* | 0.1.\* or 0.2.\*         |

## Quick Start

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
    .max_time_to_live(7 * 24 * 60 * 60 * 1000_000_000) // 7 days
    .on_success(|auth_success| {
        // handle success
    })
    .build();

auth_client.login_with_options(options);
```

It opens an [Internet Identity](https://identity.internetcomputer.org) window, saves your delegation to localStorage, and then sets you up with an identity.

Then, you can use that identity to make authenticated calls using the `ic-agent::Agent`.

```rust
let identity = auth_client.identity();

let agent = Agent::builder()
    .with_url(url)
    .with_identity(identity)
    .build()?;
```

## Native (non-WebView) frontend

When using Internet Identity in a native frontend that is not a WebView, there are several differences.

- Using OS-specific APIs instead of WebAPIs via JavaScript.
- Internet Identity issues different credentials for each website, so a website is required for authentication requests.

### Implementation

1. Set `default-features` to `false` and enable the `native` feature and one of `keyring` or `pem`.

```toml
ic-auth-client = { version = "*.*.*", default-features = false, features = ["keyring", "native"] }
```

2. Use "native" constructors.

```rust
use ic_auth_client::NativeAuthClient as AuthClient;

let auth_client = AuthClient::new("native_app")?;
```
