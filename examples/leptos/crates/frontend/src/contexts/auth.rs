use ic_agent::{Identity, export::Principal};
use ic_auth_client::{AuthClient, AuthClientCreateOptions, AuthClientLoginOptions, IdleOptions};
use leptos::{
    leptos_dom::logging::{console_log, console_warn},
    prelude::*,
    task::spawn_local,
    web_sys::Url,
};
use reactive_stores::Store;
use std::sync::Arc;
use util::{
    canister_id::INTERNET_IDENTITY,
    dfx_network::{DFX_NETWORK, DfxNetwork},
};

mod backend;
pub use backend::BackendActor;

#[allow(dead_code)]
#[derive(Clone, Store)]
pub struct AuthStore {
    is_authenticated: bool,
    is_initialized: bool,
    auth_client: Option<AuthClient>,
    identity: Option<Arc<dyn Identity>>,
    principal: Option<Principal>,
    backend: Option<BackendActor>,
}

impl AuthStore {
    pub fn create(options: AuthClientCreateOptions) -> Store<AuthStore> {
        let store = Store::new(AuthStore {
            is_authenticated: false,
            is_initialized: false,
            auth_client: None,
            identity: None,
            principal: None,
            backend: None,
        });

        spawn_local(async move {
            let client = AuthClient::new_with_options(options)
                .await
                .expect("Failed to create AuthClient");
            AuthStore::update_with_client(store, client);
        });

        store
    }

    fn update_with_client(store: Store<AuthStore>, client: AuthClient) {
        let is_authenticated = client.is_authenticated();
        let identity = client.identity();
        let principal = client.principal().ok();

        spawn_local(async move {
            store.set(AuthStore {
                is_authenticated,
                is_initialized: true,
                auth_client: Some(client),
                identity: Some(identity.clone()),
                principal,
                backend: Some(BackendActor::new(identity).await),
            });
        });
    }

    pub fn login(store: Store<AuthStore>) {
        if let Some(client) = store.auth_client().get() {
            let mut client_clone = client.clone();
            let on_success = move |_| {
                console_log("Logged in successfully");
                if let Some(updated_client) = store.auth_client().get_untracked() {
                    AuthStore::update_with_client(store, updated_client);
                }
            };

            let on_error = |e| {
                if let Some(e) = e {
                    console_warn(&format!("Failed to login: {:?}", e));
                } else {
                    console_warn("Failed to login");
                }
            };

            let options = match identity_provider() {
                Some(provider) => AuthClientLoginOptions::builder().identity_provider(provider),
                None => AuthClientLoginOptions::builder(),
            };

            let options = options.on_success(on_success).on_error(on_error).build();

            client_clone.login_with_options(options); // Use the cloned client
        }
    }

    pub fn logout(store: Store<AuthStore>) {
        if let Some(client) = store.auth_client().get() {
            let mut client_clone = client.clone();
            spawn_local(async move {
                client_clone.logout(None).await;
                if let Some(updated_client) = store.auth_client().get_untracked() {
                    AuthStore::update_with_client(store, updated_client);
                }
            });
        }
    }
}

fn identity_provider() -> Option<Url> {
    // Check if we're in a browser context
    if let Some(window) = web_sys::window() {
        // Check if the network is local
        let is_local = *DFX_NETWORK == DfxNetwork::Local;

        // Check if browser is Safari
        if let Ok(user_agent) = window.navigator().user_agent() {
            let user_agent = user_agent.to_lowercase();
            let is_safari = user_agent.contains("safari")
                && !user_agent.contains("chrome")
                && !user_agent.contains("android");

            if is_local && is_safari {
                return Some(
                    Url::new(&format!(
                        "http://localhost:4943/?canisterId={}",
                        *INTERNET_IDENTITY
                    ))
                    .unwrap(),
                );
            } else if is_local {
                return Some(
                    Url::new(&format!("http://{}.localhost:4943", *INTERNET_IDENTITY)).unwrap(),
                );
            }
        }
    }

    None
}

#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let auth = AuthStore::create(AuthClientCreateOptions {
        idle_options: Some(IdleOptions::builder().disable_idle(true).build()),
        ..Default::default()
    });

    provide_context(auth);

    children()
}

/// Hook to access the AuthStore context.
pub fn use_auth() -> Result<Store<AuthStore>, String> {
    use_context::<Store<AuthStore>>().ok_or("Out of the AuthStore context".to_string())
}

/// Extension trait for AuthStore to provide a more ergonomic API
pub trait AuthStoreExt {
    fn login(self);
    fn logout(self);
}

impl AuthStoreExt for Store<AuthStore> {
    fn login(self) {
        AuthStore::login(self);
    }

    fn logout(self) {
        AuthStore::logout(self);
    }
}
