use dotenvy_macro::dotenv;
use ic_agent::{identity::AnonymousIdentity, Identity};
use ic_auth_client::{AuthClient, AuthClientLoginOptions};
use leptos::*;
use leptos_dom::logging::console_warn;
use shared::util::canister_id::internet_identity;
use std::{env, sync::Arc};
use web_sys::Url;

/// Component that provides the AuthClient to the children components
#[component]
pub fn AuthClientProvider(children: Children) -> impl IntoView {
    let auth_client: Option<AuthClient> = None;
    let (auth_client, set_auth_client) = create_signal(auth_client);

    spawn_local(async move {
        set_auth_client.set(Some(
            AuthClient::builder()
                .on_idle(|| {
                    spawn_local(async move {
                        logout().await.unwrap();
                        window().location().reload().unwrap();
                    });
                })
                .idle_timeout(20 * 60 * 1000) // 20 minutes
                .capture_scroll(true)
                .build()
                .await
                .unwrap(),
        ));
    });

    provide_context(auth_client);

    children()
}

fn auth_client() -> Result<AuthClient, AuthClientError> {
    let auth_client = match use_context::<ReadSignal<Option<AuthClient>>>() {
        Some(auth_client) => auth_client,
        None => return Err(AuthClientError::AuthClientContextError),
    };
    if let Some(auth_client) = auth_client.get_untracked() {
        Ok(auth_client)
    } else {
        Err(AuthClientError::AuthClientNotInitialized)
    }
}

pub fn get_identity() -> Arc<dyn Identity> {
    match auth_client() {
        Ok(auth_client) => auth_client.identity(),
        Err(_) => Arc::new(AnonymousIdentity),
    }
}

pub fn login() -> Result<(), AuthClientError> {
    let mut dfx_network = dotenv!("DFX_NETWORK").to_string();
    if dfx_network.is_empty() {
        dfx_network = env::var("DFX_NETWORK").expect("DFX_NETWORK is must be set");
    }

    let identity_provider = match dfx_network.as_str() {
        "local" => Some({
            let port = 4943;
            let canister_id = internet_identity();
            Url::new(&format!("http://{}.localhost:{}", canister_id, port)).unwrap()
        }),
        "ic" => None,
        _ => panic!("Unknown dfx network: {}", dfx_network),
    };

    let on_success = |_| {
        window().location().reload().unwrap();
    };
    let on_error = |e| {
        if let Some(e) = e {
            console_warn(&format!("Failed to login: {:?}", e));
        } else {
            console_warn("Failed to login");
        }
    };

    let options = match identity_provider {
        Some(identity_provider) => AuthClientLoginOptions::builder().identity_provider(identity_provider),
        None => AuthClientLoginOptions::builder(),
    };
    let options = options
        .on_success(on_success)
        .on_error(on_error)
        .build();

    auth_client()?.login_with_options(options);

    Ok(())
}

pub async fn logout() -> Result<(), AuthClientError> {
    auth_client()?.logout(Some(window().location())).await;
    Ok(())
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthClientError {
    #[error("Out of auth client context")]
    AuthClientContextError,
    #[error("Auth client not initialized")]
    AuthClientNotInitialized,
}
