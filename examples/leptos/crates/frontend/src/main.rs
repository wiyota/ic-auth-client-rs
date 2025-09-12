use leptos::prelude::*;
use leptos_fetch::QueryClient;
use leptos_meta::*;

mod contexts;
mod features;
mod routes;

use contexts::auth::AuthProvider;
use routes::AppRouter;

#[component]
fn App() -> impl IntoView {
    QueryClient::new().provide();

    view! {
        <AppRouter />
    }
}

#[component]
fn Providers() -> impl IntoView {
    provide_meta_context();

    view! {
        <AuthProvider>
            <App />
        </AuthProvider>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();

    mount_to_body(|| view! { <Providers /> });
}
