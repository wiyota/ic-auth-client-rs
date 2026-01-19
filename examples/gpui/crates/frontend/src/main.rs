use anyhow::Result;
use gpui::prelude::*;
use gpui::{App, Application, Context, Entity, Render, WeakEntity, Window, WindowOptions, div};
use gpui_component::{
    Root,
    button::Button,
    checkbox::Checkbox,
    h_flex,
    input::{Input, InputState},
    v_flex,
};
use keyring::set_default_credential_builder;
use tracing_subscriber::EnvFilter;

mod auth;

use auth::{Auth, AuthState, TodoItem};

fn main() {
    if util::dfx_network::is_local_dfx() {
        set_default_credential_builder(keyring::mock::default_credential_builder());
    }
    if let Err(err) = run() {
        eprintln!("gpui example failed: {err}");
    }
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        cx.open_window(WindowOptions::default(), |window, cx| {
            let app_view = cx.new(|cx| TodoApp::new(window, cx));
            cx.new(|cx| Root::new(app_view, window, cx))
        })
        .expect("Failed to open window");
        cx.activate(true);
    });

    Ok(())
}

struct TodoApp {
    auth: Auth,
    todos: Vec<TodoItem>,
    draft_input: Entity<InputState>,
    status: String,
    error: Option<String>,
}

impl TodoApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let auth = Auth::new().expect("Failed to initialize auth client");
        let draft_input = cx.new(|cx| InputState::new(window, cx).placeholder("Add a new todo"));
        Self {
            auth,
            todos: Vec::new(),
            draft_input,
            status: "Ready".to_string(),
            error: None,
        }
    }

    fn sync_auth_state(&mut self, cx: &mut Context<Self>) {
        if self.auth.update_state_signal() {
            match self.auth.state {
                AuthState::Authenticated(_) => self.refresh_todos(cx),
                AuthState::Unauthenticated => {
                    self.todos.clear();
                }
                AuthState::Authenticating => {}
            }
        }
    }

    fn refresh_todos(&mut self, cx: &mut Context<Self>) {
        let backend = self.auth.backend.clone();
        self.status = "Loading todos...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.list_todos().await;
            this.update(cx, |view, _cx| match result {
                Ok(items) => {
                    view.todos = items;
                    view.status = "Loaded".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to load todos: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn login(&mut self, cx: &mut Context<Self>) {
        self.status = "Opening Internet Identity...".to_string();
        if let Err(err) = self.auth.login() {
            self.error = Some(format!("Login failed: {err}"));
            self.status = "Error".to_string();
        } else {
            self.sync_auth_state(cx);
        }
    }

    fn logout(&mut self) {
        if let Err(err) = self.auth.logout() {
            self.error = Some(format!("Logout failed: {err}"));
            self.status = "Error".to_string();
        } else {
            self.status = "Logged out".to_string();
            self.todos.clear();
        }
    }

    fn add_todo(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.draft_input.read(cx).value().to_string();
        let text = text.trim().to_string();
        if text.is_empty() {
            self.error = Some("Todo text cannot be empty".to_string());
            return;
        }

        let backend = self.auth.backend.clone();
        self.draft_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        self.status = "Adding todo...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.add_todo(text).await;
            this.update(cx, |view, _cx| match result {
                Ok(item) => {
                    view.todos.push(item);
                    view.status = "Saved".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to add todo: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn toggle_todo(&mut self, cx: &mut Context<Self>, id: u64) {
        let backend = self.auth.backend.clone();
        self.status = "Updating todo...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.toggle_todo(id).await;
            this.update(cx, |view, _cx| match result {
                Ok(Some(updated)) => {
                    if let Some(item) = view.todos.iter_mut().find(|item| item.id == id) {
                        *item = updated;
                    }
                    view.status = "Updated".to_string();
                }
                Ok(None) => {
                    view.error = Some("Todo not found".to_string());
                    view.status = "Error".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to update todo: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn delete_todo(&mut self, cx: &mut Context<Self>, id: u64) {
        let backend = self.auth.backend.clone();
        self.status = "Deleting todo...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.delete_todo(id).await;
            this.update(cx, |view, _cx| match result {
                Ok(true) => {
                    view.todos.retain(|item| item.id != id);
                    view.status = "Deleted".to_string();
                }
                Ok(false) => {
                    view.error = Some("Todo not found".to_string());
                    view.status = "Error".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to delete todo: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn render_todo_row(&self, cx: &Context<Self>, item: &TodoItem) -> impl gpui::IntoElement {
        let id = item.id;
        let completed = item.completed;
        let text = item.text.clone();

        h_flex()
            .gap_2()
            .child(
                Checkbox::new(("todo", id))
                    .checked(completed)
                    .on_click(cx.listener(move |view, _checked, _window, cx| {
                        view.toggle_todo(cx, id);
                    })),
            )
            .child(div().child(text))
            .child(
                Button::new("Delete").on_click(cx.listener(move |view, _event, _window, cx| {
                    view.delete_todo(cx, id);
                })),
            )
    }
}

impl Render for TodoApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl gpui::IntoElement {
        self.sync_auth_state(cx);

        let header = div().child("IC GPUI APP");
        let status = div().child(self.status.clone());
        let error = self
            .error
            .as_ref()
            .map(|err| div().child(err.clone()))
            .unwrap_or_else(|| div());

        let auth_controls = match &self.auth.state {
            AuthState::Authenticated(principal) => h_flex()
                .gap_2()
                .child(div().child(format!("Logged in: {principal}")))
                .child(Button::new("Logout").on_click(cx.listener(
                    |view, _event, _window, _cx| {
                        view.logout();
                    },
                ))),
            AuthState::Authenticating => h_flex().child(div().child("Logging in...")),
            AuthState::Unauthenticated => h_flex().gap_2().child(
                Button::new("Log in with II")
                    .on_click(cx.listener(|view, _event, _window, cx| view.login(cx))),
            ),
        };

        let input_row = h_flex().gap_2().child(Input::new(&self.draft_input)).child(
            Button::new("Add").on_click(cx.listener(|view, _event, window, cx| {
                view.add_todo(window, cx);
            })),
        );

        let todo_list = v_flex().gap_1p5().children(
            self.todos
                .iter()
                .map(|item| self.render_todo_row(cx, item))
                .collect::<Vec<_>>(),
        );

        v_flex()
            .gap_3()
            .child(header)
            .child(auth_controls)
            .child(status)
            .child(error)
            .child(input_row)
            .child(todo_list)
    }
}
