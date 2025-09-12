use leptos::prelude::*;
use leptos_router::{
    path,
    components::{Route, Router, FlatRoutes}
};

pub mod index;

#[component]
pub fn AppRouter() -> impl IntoView {
    view! {
        <Router>
            <FlatRoutes fallback=|| "This page could not be found.">
                <Route path=path!("/") view=index::Route />
            </FlatRoutes>
        </Router>
    }
}
