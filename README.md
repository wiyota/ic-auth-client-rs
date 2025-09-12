# ic-auth-client

Port of [@dfinity/auth-client](https://www.npmjs.com/package/@dfinity/auth-client) for the Rust programming language.

This is a crate for developers who build the frontend of applications for Internet Computer using Rust as the primary language within a Web browser or Webview environment.

If you use JavaScript for frontend, you can use the Internet Identity Service compatible libraries such as [@dfinity/auth-client](https://www.npmjs.com/package/@dfinity/auth-client) or [@nfid/identitykit](https://www.npmjs.com/package/@nfid/identitykit).

For native Rust frontend that does not have access to [Browser APIs](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Client-side_web_APIs/Introduction#apis_in_client-side_javascript), this crate cannot be used, but you may create your own implementation by referring to the structs included in the code.

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
