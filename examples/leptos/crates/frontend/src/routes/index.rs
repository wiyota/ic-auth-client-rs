use crate::{
    contexts::auth::{use_auth, AuthStoreStoreFields},
    features::{
        note::component::NoteComponent,
        user::account::{LoginButton, LogoutButton},
    },
};
use leptos::prelude::*;

#[component]
pub fn Route() -> impl IntoView {
    let auth = use_auth().unwrap();
    let is_authenticated = auth.is_authenticated();
    let principal = auth.principal();

    view! {
        <main class="flex flex-col justify-center items-center p-8 w-screen h-screen">
            <h1 class="text-4xl font-semibold text-center cursor-default">"ic-auth-client for Rust Example"</h1>

                <section
                    class="flex flex-col gap-6 justify-center items-center w-full text-center max-w-[60rem]"
                    class:flex-grow=move || is_authenticated.get()
                >
                    {move || {
                        if is_authenticated.get() {
                            view! {
                                <div class="flex flex-col gap-2 items-center">
                                    <p class="text-xs pointer-events-none text-stone-600 dark:text-stone-400">{format!("You're logged in: {}", principal.get().unwrap())}</p>
                                    <LogoutButton />
                                </div>

                                <NoteComponent />
                            }.into_any()
                        } else {
                            view! {
                                <div class="flex flex-col gap-2 items-center">
                                    <p class="text-xs pointer-events-none text-stone-600 dark:text-stone-400">"You're NOT logged in"</p>
                                    <LoginButton />
                                </div>
                            }.into_any()
                        }
                    }}
                </section>
        </main>
    }
}
