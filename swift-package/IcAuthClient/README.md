# IcAuthClient (Swift Package)

Swift Package Manager wrapper for the UniFFI-generated Swift bindings of
`ic-auth-client`. This package includes:

- `IcAuthClient` Swift target (generated bindings + hand-written helpers).
- `IcAuthClientFFI` binary target (xcframework built from Rust).

## Requirements

- macOS 13+ / iOS 16+
- Xcode 15+ (Swift tools 5.9)

## Build the xcframework

From the repo root:

```sh
swift-package/IcAuthClient/build_all.sh
```

This does:

1. `./uniffi/generate_swift.sh` to generate Swift bindings.
2. `sync_uniffi_swift.sh` to sync generated Swift into `Sources/IcAuthClient`.
3. `build_xcframework.sh` to build `IcAuthClientFFI.xcframework`.

## Run tests

```sh
cd swift-package/IcAuthClient
swift test
```

The integration test uses keyring storage and clears the test service
name before and after the run.

## Usage

Basic usage (macOS / iOS):

```swift
import IcAuthClient

let client = try AuthClient.newKeyring(serviceName: "my-app")

let options = LoginOptions(
    identityProvider: nil,
    maxTimeToLive: nil,
    allowPinAuthentication: nil,
    derivationOrigin: nil,
    windowOpenerFeatures: nil,
    timeoutMillis: nil,
    customValuesJson: nil
)

let loginUrl = try client.buildLoginUrl(
    iiUrl: "https://id.ai",
    redirectUri: "myapp://auth",
    options: options
)
```

On iOS/macOS, `AuthSession` wraps `ASWebAuthenticationSession`:

```swift
let session = AuthSession(client: client)
session.login(
    iiUrl: "https://id.ai",
    redirectUri: "myapp://auth",
    options: options,
    window: window
) { result in
    // handle result
}
```

## Notes

- The default key type for Swift `newKeyring` is `Secp256k1`.
- If you need to regenerate bindings or rebuild the xcframework, use
  `build_all.sh`.
