use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router_macro::path;

pub mod index;

#[component]
pub fn AppRouter() -> impl IntoView {
    view! {
        <Router>
            <Routes fallback=|| "This page could not be found.">
                <Route path=path!("/") view=index::Route />
            </Routes>
        </Router>
    }
}
