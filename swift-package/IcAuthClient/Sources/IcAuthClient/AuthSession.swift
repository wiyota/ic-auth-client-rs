import AuthenticationServices
import Foundation

#if os(iOS)
    import UIKit
#elseif os(macOS)
    import AppKit
#endif

@MainActor
public final class AuthSession: NSObject {
    private let client: AuthClient
    private var session: ASWebAuthenticationSession?
    private var presentationContext: ASWebAuthenticationPresentationContextProviding?

    public init(client: AuthClient) {
        self.client = client
    }

    #if os(iOS)
        public func login(
            iiUrl: String,
            redirectUri: String,
            options: LoginOptions,
            window: UIWindow,
            completion: @escaping (Result<Void, Error>) -> Void
        ) {
            startSession(
                iiUrl: iiUrl,
                redirectUri: redirectUri,
                options: options,
                presentation: WindowPresentationContext(window: window),
                completion: completion
            )
        }
    #endif

    #if os(macOS)
        public func login(
            iiUrl: String,
            redirectUri: String,
            options: LoginOptions,
            window: NSWindow,
            completion: @escaping (Result<Void, Error>) -> Void
        ) {
            startSession(
                iiUrl: iiUrl,
                redirectUri: redirectUri,
                options: options,
                presentation: WindowPresentationContext(window: window),
                completion: completion
            )
        }
    #endif

    private func startSession(
        iiUrl: String,
        redirectUri: String,
        options: LoginOptions,
        presentation: ASWebAuthenticationPresentationContextProviding,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        do {
            let loginUrl = try client.buildLoginUrl(
                iiUrl: iiUrl,
                redirectUri: redirectUri,
                options: options
            )

            guard let url = URL(string: loginUrl) else {
                completion(.failure(NSError(domain: "AuthSession", code: 1)))
                return
            }

            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: URL(string: redirectUri)?.scheme
            ) { [weak self] callbackURL, error in
                if let error {
                    completion(.failure(error))
                    return
                }

                guard let callbackURL,
                    let payload = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?
                        .queryItems?
                        .first(where: { $0.name == "payload" })?.value
                else {
                    completion(.failure(NSError(domain: "AuthSession", code: 2)))
                    return
                }

                do {
                    try self?.client.finishLoginFromPayload(payload: payload)
                    completion(.success(()))
                } catch {
                    completion(.failure(error))
                }
            }

            session.presentationContextProvider = presentation
            session.prefersEphemeralWebBrowserSession = true
            session.start()
            self.session = session
            self.presentationContext = presentation
        } catch {
            completion(.failure(error))
        }
    }
}

#if os(iOS)
    private final class WindowPresentationContext: NSObject,
        ASWebAuthenticationPresentationContextProviding
    {
        private weak var window: UIWindow?

        init(window: UIWindow) {
            self.window = window
        }

        func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
            return window ?? ASPresentationAnchor()
        }
    }
#elseif os(macOS)
    private final class WindowPresentationContext: NSObject,
        ASWebAuthenticationPresentationContextProviding
    {
        private weak var window: NSWindow?

        init(window: NSWindow) {
            self.window = window
        }

        func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
            return window ?? ASPresentationAnchor()
        }
    }
#endif
