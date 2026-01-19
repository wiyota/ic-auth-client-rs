use dioxus::prelude::*;
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt;
use ic_agent::export::Principal;
use ic_auth_client::{AuthClient, AuthClientCreateOptions, AuthClientLoginOptions};
use wasm_bindgen_futures::spawn_local;

const AUTH_POPUP_HEIGHT: u32 = 625;
const AUTH_POPUP_WIDTH: u32 = 576;
const IDENTITY_PROVIDER: &str = "https://id.ai";

#[derive(Debug)]
enum AuthEvent {
    Success,
    Error(Option<String>),
}

fn main() {
    console_error_panic_hook::set_once();
    launch(App);
}

#[component]
fn App() -> Element {
    let mut auth_client = use_signal(|| None::<AuthClient>);
    let mut status = use_signal(|| "Initializing auth client...".to_string());
    let mut is_authenticated = use_signal(|| false);
    let mut principal = use_signal(|| None::<Principal>);

    let auth_events = use_coroutine({
        move |mut rx: UnboundedReceiver<AuthEvent>| async move {
            while let Some(event) = rx.next().await {
                match event {
                    AuthEvent::Success => {
                        if let Some(client) = auth_client.read().clone() {
                            let authed = client.is_authenticated();
                            principal.set(client.principal().ok());
                            is_authenticated.set(authed);
                            status.set(status_text(authed));
                        }
                    }
                    AuthEvent::Error(err) => {
                        if let Some(err) = err {
                            status.set(format!("Login failed: {err}"));
                        } else {
                            status.set("Login failed".to_string());
                        }
                    }
                }
            }
        }
    });

    use_future(move || async move {
        match AuthClient::new_with_options(AuthClientCreateOptions::default()).await {
            Ok(client) => {
                let authed = client.is_authenticated();
                let principal_value = client.principal().ok();
                is_authenticated.set(authed);
                principal.set(principal_value);
                status.set(status_text(authed));
                auth_client.set(Some(client));
            }
            Err(err) => {
                status.set(format!("Failed to init AuthClient: {err}"));
            }
        }
    });

    let authed = *is_authenticated.read();
    let principal_text = principal.read().as_ref().map(|value| value.to_text());
    let status_text = status.read().clone();
    let status_badge = if authed {
        "badge badge-success"
    } else {
        "badge badge-ghost"
    };
    let principal_display = principal_text
        .clone()
        .unwrap_or_else(|| "Not signed in".to_string());

    let login_disabled = auth_client.read().is_none() || authed;
    let logout_disabled = auth_client.read().is_none() || !authed;

    rsx! {
        main { class: "min-h-screen bg-base-200",
            header { class: "navbar bg-base-100 backdrop-blur border-b border-base-300 sticky top-0 z-10",
                div { class: "navbar-start",
                    span { class: "text-xl font-semibold tracking-tight", "ic-auth-client" }
                }
                div { class: "navbar-end",
                    span { class: "badge badge-outline", "Dioxus" }
                }
            }
            section { class: "mx-auto max-w-5xl px-6 py-10 space-y-8",
                div { class: "grid gap-6 lg:grid-cols-[1.2fr_0.8fr]",
                    div { class: "card bg-base-100 shadow-xl",
                        div { class: "card-body space-y-4",
                            h1 { class: "card-title text-2xl", "Auth Client Demo" }
                            p { class: "text-base-content/80",
                                "Sign in with Internet Identity to unlock backend actions and canister calls."
                            }
                            div { class: "flex flex-wrap items-center gap-2",
                                span { class: "{status_badge}", "{status_text}" }
                                span { class: "badge badge-ghost", "Provider: {IDENTITY_PROVIDER}" }
                            }
                            div { class: "rounded-2xl bg-base-200 p-4 space-y-2",
                                p { class: "text-sm uppercase tracking-wide text-base-content/60",
                                    "Principal"
                                }
                                code { class: "font-mono text-sm break-all", "{principal_display}" }
                            }
                        }
                    }
                    div { class: "card bg-base-100 shadow-xl",
                        div { class: "card-body space-y-4",
                            h2 { class: "card-title text-xl", "Session Actions" }
                            p { class: "text-base-content/70",
                                "Launch a centered popup to authenticate, then reuse the session to call backend canisters."
                            }
                            div { class: "flex flex-wrap gap-3",
                                button {
                                    class: "btn btn-primary",
                                    disabled: login_disabled,
                                    onclick: move |_| login(auth_client, status, auth_events.tx()),
                                    "Login"
                                }
                                button {
                                    class: "btn btn-outline",
                                    disabled: logout_disabled,
                                    onclick: move |_| logout(auth_client, status, is_authenticated, principal),
                                    "Logout"
                                }
                            }
                            div { class: "text-sm text-base-content/60",
                                "Popup size: {AUTH_POPUP_WIDTH}x{AUTH_POPUP_HEIGHT}"
                            }
                        }
                    }
                }
                div { class: "grid gap-4 lg:grid-cols-3",
                    div { class: "card bg-base-100 border border-base-300",
                        div { class: "card-body",
                            h3 { class: "font-semibold", "Frontend" }
                            p { class: "text-sm text-base-content/70",
                                "Dioxus CLI + Tailwind + daisyUI styling."
                            }
                        }
                    }
                    div { class: "card bg-base-100 border border-base-300",
                        div { class: "card-body",
                            h3 { class: "font-semibold", "Backend" }
                            p { class: "text-sm text-base-content/70",
                                "Rust canister with stable memory for notes and account data."
                            }
                        }
                    }
                    div { class: "card bg-base-100 border border-base-300",
                        div { class: "card-body",
                            h3 { class: "font-semibold", "Canisters" }
                            p { class: "text-sm text-base-content/70",
                                "Assets + backend + Internet Identity ready for local dfx."
                            }
                        }
                    }
                }
            }
        }
    }
}

fn login(
    auth_client: Signal<Option<AuthClient>>,
    mut status: Signal<String>,
    auth_events: UnboundedSender<AuthEvent>,
) {
    let Some(client) = auth_client.read().clone() else {
        status.set("Auth client not ready".to_string());
        return;
    };

    status.set("Opening Internet Identity...".to_string());

    let on_success_events = auth_events.clone();
    let on_error_events = auth_events.clone();

    let on_success = move |_| {
        let _ = on_success_events.unbounded_send(AuthEvent::Success);
    };

    let on_error = move |err: Option<String>| {
        let _ = on_error_events.unbounded_send(AuthEvent::Error(err));
    };

    let options = AuthClientLoginOptions::builder()
        .identity_provider(IDENTITY_PROVIDER.to_string())
        .window_opener_features(popup_center(AUTH_POPUP_WIDTH, AUTH_POPUP_HEIGHT))
        .on_success(on_success)
        .on_error(on_error)
        .build();

    client.login_with_options(options);
}

fn logout(
    auth_client: Signal<Option<AuthClient>>,
    mut status: Signal<String>,
    mut is_authenticated: Signal<bool>,
    mut principal: Signal<Option<Principal>>,
) {
    let Some(client) = auth_client.read().clone() else {
        status.set("Auth client not ready".to_string());
        return;
    };

    status.set("Logging out...".to_string());

    spawn_local(async move {
        client.logout(None).await;
        let authed = client.is_authenticated();
        principal.set(client.principal().ok());
        is_authenticated.set(authed);
        status.set(status_text(authed));
    });
}

fn status_text(is_authenticated: bool) -> String {
    if is_authenticated {
        "Authenticated".to_string()
    } else {
        "Unauthenticated".to_string()
    }
}

fn popup_center(width: u32, height: u32) -> String {
    let window = web_sys::window();
    let (screen_width, screen_height) = match window {
        Some(window) => (
            window
                .inner_width()
                .ok()
                .and_then(|value| value.as_f64())
                .unwrap_or(1200.0) as u32,
            window
                .inner_height()
                .ok()
                .and_then(|value| value.as_f64())
                .unwrap_or(800.0) as u32,
        ),
        None => (1200, 800),
    };

    let left = (screen_width.saturating_sub(width)) / 2;
    let top = (screen_height.saturating_sub(height)) / 2;

    format!(
        "toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no, copyhistory=no, width={width}, height={height}, top={top}, left={left}"
    )
}
