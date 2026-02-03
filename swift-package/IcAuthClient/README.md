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

On iOS/macOS, `AuthSession` can open the default browser (recommended) or
use `WKWebView`:

```swift
let session = AuthSession(client: client)
session.login(
    iiUrl: "https://id.ai",
    redirectUri: "myapp://auth",
    options: options,
    window: window,
    mode: .defaultBrowser
) { result in
    // handle result
}
```

When using `.defaultBrowser`, forward the callback URL back to the session
so it can finish the login:

```swift
// e.g. in a SwiftUI view
.onOpenURL { url in
    session.handleCallbackUrl(url)
}
```

On macOS, if you use an `NSApplicationDelegate`, also forward URLs from
`application(_:open:)` to the same handler:

```swift
final class AppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            session.handleCallbackUrl(url)
        }
    }
}
```

Make sure the URL scheme in `redirectUri` is registered by your app
(Info.plist `CFBundleURLTypes`). The scheme can be any custom value (for example
`myapp://auth`), but it must match your app’s registered URL schemes exactly.
If it isn’t registered, the browser can’t redirect back to your app and the
login will fail.

In the browser, you may also see console warnings about CORS or `fetch` failing
for the custom scheme; the bridge falls back to a redirect with a `payload`
query parameter, so the redirect must be allowed for the flow to complete.

## Notes

- The default key type for Swift `newKeyring` is `Secp256k1`.
- If you need to regenerate bindings or rebuild the xcframework, use
  `build_all.sh`.
