extern crate console_error_panic_hook;

use crate::{
    components::{account::{LoginButton, LogoutButton}, note::NoteSection},
    stores::{agent::AgentProvider, auth_client::AuthClientProvider},
};
use ic_auth_client::AuthClient;
use leptos::*;
use leptos_meta::*;

mod components;
mod stores;

#[component]
fn App() -> impl IntoView {
    let auth_client = use_context::<ReadSignal<Option<AuthClient>>>().unwrap();
    let is_authenticated = move || {
        auth_client
            .get()
            .map(|auth_client| auth_client.is_authenticated())
    };

    view! {
        <main class="flex flex-col justify-center items-center p-8 w-screen h-screen">
            <h1 class="mb-4 text-4xl font-semibold text-center pointer-events-none">"ic-auth-client for Rust Example"</h1>
            <section
                class="flex flex-col gap-6 justify-center items-center w-full text-center max-w-[60rem]"
                class:flex-grow=move || is_authenticated().map_or(false, |b| b)
            >
                {move || {
                    if let Some(is_authenticated) = is_authenticated() {
                        if is_authenticated {
                            view! {
                                <div class="flex flex-col gap-2 items-center">
                                    <p class="text-xs pointer-events-none text-stone-600 dark:text-stone-400">"You're logged in"</p>
                                    <LogoutButton />
                                </div>

                                <NoteSection />
                            }.into_view()
                        } else {
                            view! {
                                <div class="flex flex-col gap-2 items-center">
                                    <p class="text-xs pointer-events-none text-stone-600 dark:text-stone-400">"You're NOT logged in"</p>
                                    <LoginButton />
                                </div>
                            }.into_view()
                        }
                    } else {
                        ().into_view()
                    }
                }}
            </section>
        </main>
    }
}

#[component]
fn Providers() -> impl IntoView {
    provide_meta_context();

    view! {
        <AuthClientProvider>
            <AgentProvider>
                <App />
            </AgentProvider>
        </AuthClientProvider>
    }
}

fn main() {
    if leptos_dom::is_dev() {
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    }

    mount_to_body(|| view! { <Providers /> });
}
