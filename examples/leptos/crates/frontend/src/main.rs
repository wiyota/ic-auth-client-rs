use leptos::prelude::*;
use leptos_meta::*;

mod contexts;
mod features;
mod routes;

use contexts::auth::AuthProvider;
use routes::AppRouter;

#[component]
fn App() -> impl IntoView {
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

    mount_to_body(|| view! { <Providers /> });
}
