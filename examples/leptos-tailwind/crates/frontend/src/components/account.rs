use crate::stores::auth_client::{login, logout};
use leptos::*;

#[component]
pub fn LoginButton() -> impl IntoView {
    let action = Action::new(|_| async { login().await });

    view! {
        <button
            class="py-1 w-36 text-base rounded hover:bg-blue-500 active:bg-blue-700 bg-stone-300 text-md dark:bg-stone-700 dark:hover:text-stone-100 dark:hover:bg-blue-600 dark:active:bg-blue-800 hover:text-stone-100"
            on:click=move |_| { action.dispatch(()) }
        >
            "Login"
        </button>
    }
}

#[component]
pub fn LogoutButton() -> impl IntoView {
    let action = Action::new(|_| async {
        logout().await.unwrap();
        window().location().reload().unwrap();
    });

    view! {
        <button
            class="py-1 w-36 text-base rounded hover:bg-blue-500 active:bg-blue-700 text-md dark:hover:text-stone-100 dark:hover:bg-blue-700 dark:active:bg-blue-800 hover:text-stone-100"
            on:click=move |_| { action.dispatch(()) }
        >
            "Logout"
        </button>
    }
}
