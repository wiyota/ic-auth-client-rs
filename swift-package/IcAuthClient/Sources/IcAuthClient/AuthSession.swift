import Foundation

#if canImport(WebKit)
    import WebKit
#endif

#if os(iOS)
    import UIKit
#elseif os(macOS)
    import AppKit
#endif

@MainActor
public final class AuthSession: NSObject {
    public enum Mode: String, CaseIterable, Sendable {
        case defaultBrowser
        case webView
    }

    private let client: AuthClient
    private var pendingCompletion: ((Result<Void, Error>) -> Void)?
    private var pendingRedirectScheme: String?

    #if os(iOS) && canImport(WebKit)
        private var webViewController: WebViewAuthController?
    #endif
    #if os(macOS) && canImport(WebKit)
        private var webViewWindowController: WebViewAuthWindowController?
    #endif

    public init(client: AuthClient) {
        self.client = client
    }

    #if os(iOS)
        public func login(
            authBridgeUrl: String,
            redirectUri: String,
            options: LoginOptions,
            window: UIWindow,
            completion: @escaping (Result<Void, Error>) -> Void
        ) {
            startSession(
                authBridgeUrl: authBridgeUrl,
                redirectUri: redirectUri,
                options: options,
                window: window,
                completion: completion
            )
        }
    #endif

    #if os(macOS)
        public func login(
            authBridgeUrl: String,
            redirectUri: String,
            options: LoginOptions,
            window: NSWindow,
            completion: @escaping (Result<Void, Error>) -> Void
        ) {
            startSession(
                authBridgeUrl: authBridgeUrl,
                redirectUri: redirectUri,
                options: options,
                window: window,
                completion: completion
            )
        }
    #endif

    private func startSession(
        authBridgeUrl: String,
        redirectUri: String,
        options: LoginOptions,
        window: AnyObject,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        do {
            let loginUrl = try client.buildLoginUrl(
                authBridgeUrl: authBridgeUrl,
                redirectUri: redirectUri,
                options: options
            )

            guard let url = URL(string: loginUrl) else {
                completion(.failure(NSError(domain: "AuthSession", code: 1)))
                return
            }

            let redirectScheme = URL(string: redirectUri)?.scheme
            pendingRedirectScheme = redirectScheme

            switch mode {
            case .defaultBrowser:
                pendingCompletion = completion
                openExternalBrowser(url: url) { [weak self] success in
                    guard let self else { return }
                    if !success {
                        self.pendingCompletion = nil
                        self.pendingRedirectScheme = nil
                        completion(.failure(NSError(domain: "AuthSession", code: 3)))
                    }
                }
            case .webView:
                #if os(iOS) && canImport(WebKit)
                    guard let window = window as? UIWindow else {
                        completion(.failure(NSError(domain: "AuthSession", code: 4)))
                        return
                    }
                    guard let root = window.rootViewController else {
                        completion(.failure(NSError(domain: "AuthSession", code: 5)))
                        return
                    }
                    pendingCompletion = completion
                    let controller = WebViewAuthController(
                        startURL: url,
                        callbackScheme: redirectScheme,
                        onCallback: { [weak self] url in
                            self?.handleCallbackUrl(url)
                        },
                        onCancel: { [weak self] in
                            guard let self else { return }
                            self.pendingCompletion = nil
                            self.pendingRedirectScheme = nil
                            completion(.failure(NSError(domain: "AuthSession", code: 6)))
                        }
                    )
                    webViewController = controller
                    root.present(controller, animated: true)
                #elseif os(macOS) && canImport(WebKit)
                    guard let window = window as? NSWindow else {
                        completion(.failure(NSError(domain: "AuthSession", code: 4)))
                        return
                    }
                    pendingCompletion = completion
                    let controller = WebViewAuthWindowController(
                        startURL: url,
                        callbackScheme: redirectScheme,
                        parentWindow: window,
                        onCallback: { [weak self] url in
                            self?.handleCallbackUrl(url)
                        },
                        onCancel: { [weak self] in
                            guard let self else { return }
                            self.pendingCompletion = nil
                            self.pendingRedirectScheme = nil
                            completion(.failure(NSError(domain: "AuthSession", code: 6)))
                        }
                    )
                    webViewWindowController = controller
                    controller.show()
                #else
                    completion(.failure(NSError(domain: "AuthSession", code: 7)))
                #endif
            }
        } catch {
            completion(.failure(error))
        }
    }

    @discardableResult
    public func handleCallbackUrl(_ url: URL) -> Bool {
        return handleCallbackUrl(url, completion: pendingCompletion)
    }

    private func handleCallbackUrl(_ url: URL, completion: ((Result<Void, Error>) -> Void)?) -> Bool
    {
        if let expectedScheme = pendingRedirectScheme, url.scheme != expectedScheme {
            return false
        }

        guard
            let payload = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "payload" })?.value
        else {
            completion?(.failure(NSError(domain: "AuthSession", code: 2)))
            pendingCompletion = nil
            pendingRedirectScheme = nil
            return false
        }

        do {
            try client.finishLoginFromPayload(payload: payload)
            completion?(.success(()))
            pendingCompletion = nil
            pendingRedirectScheme = nil
            return true
        } catch {
            completion?(.failure(error))
            pendingCompletion = nil
            pendingRedirectScheme = nil
            return false
        }
    }

    private func openExternalBrowser(url: URL, completion: @escaping (Bool) -> Void) {
        #if os(iOS)
            UIApplication.shared.open(url, options: [:]) { success in
                completion(success)
            }
        #elseif os(macOS)
            completion(NSWorkspace.shared.open(url))
        #else
            completion(false)
        #endif
    }
}

#if os(iOS) && canImport(WebKit)
    private final class WebViewAuthController: UIViewController, WKNavigationDelegate, WKUIDelegate
    {
        private let startURL: URL
        private let callbackScheme: String?
        private let onCallback: (URL) -> Void
        private let onCancel: () -> Void
        private var webView: WKWebView?

        init(
            startURL: URL,
            callbackScheme: String?,
            onCallback: @escaping (URL) -> Void,
            onCancel: @escaping () -> Void
        ) {
            self.startURL = startURL
            self.callbackScheme = callbackScheme
            self.onCallback = onCallback
            self.onCancel = onCancel
            super.init(nibName: nil, bundle: nil)
            modalPresentationStyle = .pageSheet
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) {
            fatalError("init(coder:) has not been implemented")
        }

        override func viewDidLoad() {
            super.viewDidLoad()

            let configuration = WKWebViewConfiguration()
            let webView = WKWebView(frame: .zero, configuration: configuration)
            webView.navigationDelegate = self
            webView.uiDelegate = self
            webView.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(webView)
            NSLayoutConstraint.activate([
                webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                webView.topAnchor.constraint(equalTo: view.topAnchor),
                webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            ])
            self.webView = webView

            let closeButton = UIButton(type: .system)
            closeButton.setTitle("Close", for: .normal)
            closeButton.addTarget(self, action: #selector(handleClose), for: .touchUpInside)
            closeButton.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(closeButton)
            NSLayoutConstraint.activate([
                closeButton.leadingAnchor.constraint(
                    equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 12),
                closeButton.topAnchor.constraint(
                    equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 12),
            ])

            webView.load(URLRequest(url: startURL))
        }

        @objc private func handleClose() {
            onCancel()
            dismiss(animated: true)
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            if navigationAction.targetFrame == nil, let url = navigationAction.request.url {
                webView.load(URLRequest(url: url))
                decisionHandler(.cancel)
                return
            }

            if let url = navigationAction.request.url,
                let scheme = url.scheme,
                scheme == callbackScheme
            {
                onCallback(url)
                dismiss(animated: true)
                decisionHandler(.cancel)
                return
            }

            decisionHandler(.allow)
        }
    }
#endif

#if os(macOS) && canImport(WebKit)
    private final class WebViewAuthWindowController: NSObject, NSWindowDelegate,
        WKNavigationDelegate,
        WKUIDelegate
    {
        private let startURL: URL
        private let callbackScheme: String?
        private let parentWindow: NSWindow
        private let onCallback: (URL) -> Void
        private let onCancel: () -> Void
        private let window: NSWindow
        private let webView: WKWebView
        private var didComplete = false

        init(
            startURL: URL,
            callbackScheme: String?,
            parentWindow: NSWindow,
            onCallback: @escaping (URL) -> Void,
            onCancel: @escaping () -> Void
        ) {
            self.startURL = startURL
            self.callbackScheme = callbackScheme
            self.parentWindow = parentWindow
            self.onCallback = onCallback
            self.onCancel = onCancel

            let configuration = WKWebViewConfiguration()
            self.webView = WKWebView(frame: .zero, configuration: configuration)
            let viewController = NSViewController()
            viewController.view = webView

            self.window = NSWindow(contentViewController: viewController)
            self.window.title = "Authentication"
            self.window.setContentSize(NSSize(width: 900, height: 700))
            self.window.styleMask.insert(.closable)
            self.window.styleMask.insert(.titled)

            super.init()

            webView.navigationDelegate = self
            webView.uiDelegate = self
            self.window.delegate = self
        }

        func show() {
            parentWindow.beginSheet(window, completionHandler: nil)
            webView.load(URLRequest(url: startURL))
        }

        func windowWillClose(_ notification: Notification) {
            if !didComplete {
                onCancel()
            }
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            if navigationAction.targetFrame == nil, let url = navigationAction.request.url {
                webView.load(URLRequest(url: url))
                decisionHandler(.cancel)
                return
            }

            if let url = navigationAction.request.url,
                let scheme = url.scheme,
                scheme == callbackScheme
            {
                didComplete = true
                onCallback(url)
                parentWindow.endSheet(window)
                decisionHandler(.cancel)
                return
            }

            decisionHandler(.allow)
        }
    }
#endif
