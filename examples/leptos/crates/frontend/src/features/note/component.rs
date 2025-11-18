use crate::contexts::auth::{AuthStore, AuthStoreFields, use_auth};
use domain::note::{NoteId, NoteTitle, entity::Note};
use leptos::{
    either::Either,
    html::{Input, Textarea},
    leptos_dom::logging::console_warn,
    prelude::*,
    task::spawn_local,
};
use leptos_fetch::QueryClient;
use std::collections::BTreeMap;

async fn fetch_note(id: Option<NoteId>) -> Option<Note> {
    use_auth()
        .unwrap()
        .backend()
        .get_untracked()?
        .fetch_note(id?)
        .await
}

async fn fetch_note_list() -> Vec<(NoteId, NoteTitle)> {
    match use_auth().unwrap().backend().get_untracked() {
        Some(backend) => backend.fetch_note_list().await,
        None => {
            console_warn("Backend is not available");
            Vec::new()
        }
    }
}

type PostNote = Action<(AuthStore, Note), ()>;

#[component]
pub fn NoteComponent() -> impl IntoView {
    let list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>> = RwSignal::new(BTreeMap::new());
    let active_note_id: RwSignal<Option<NoteId>> = RwSignal::new(None);
    let (is_init, set_is_init) = signal(true);

    let title_input = NodeRef::<Input>::new();
    let content_input = NodeRef::<Textarea>::new();

    let check_title_validity = Trigger::new();

    let client: QueryClient = expect_context();
    let note_list_resource = client.resource(fetch_note_list, || ());
    let note_resource = client.resource(fetch_note, move || active_note_id.get());

    {
        spawn_local(async move {
            let notes = note_list_resource.await;
            let res = notes
                .into_iter()
                .map(|(note_id, note_title)| (note_id, RwSignal::new(note_title)))
                .collect();

            list.set(res);
            set_is_init.set(false);
        });
    }

    let post_note = Action::new(|input: &(AuthStore, Note)| {
        let (auth_store, note) = input.clone();
        let note_id = note.id;
        let client: QueryClient = expect_context();

        async move {
            let cached_note = client.fetch_query(fetch_note, Some(note_id)).await;

            if let Some(cached_note) = cached_note
                && note == cached_note
            {
                return;
            }

            client.set_query(fetch_note, Some(note_id), Some(note.clone()));

            let backend = auth_store.backend();
            match backend.get_untracked() {
                Some(backend) => {
                    backend.post_note(note).await;
                    client.invalidate_query(fetch_note, Some(note_id));
                }
                None => console_warn("BackendActor is not available"),
            };
        }
    });

    view! {
        <article class="rounded-box flex border border-stone-300 dark:border-stone-600 w-full h-full">
            <NoteList list active_note_id note_resource post_note title_input content_input is_init check_title_validity />
            <NoteEditor list active_note_id note_resource post_note title_input content_input is_init check_title_validity />
        </article>
    }
}

#[component]
fn NoteList(
    list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>>,
    active_note_id: RwSignal<Option<NoteId>>,
    note_resource: Resource<Option<Note>>,
    post_note: PostNote,
    title_input: NodeRef<Input>,
    content_input: NodeRef<Textarea>,
    is_init: ReadSignal<bool>,
    check_title_validity: Trigger,
) -> impl IntoView {
    let auth = use_auth().unwrap();

    let button_class = move || {
        format!(
            "btn btn-sm py-[0.125rem] px-4 mb-2 w-full {}",
            if is_init.get() {
                "text-stone-500 dark:text-stone-600 bg-stone-200 dark:bg-stone-800"
            } else {
                "border-stone-300 text-stone-700 dark:border-stone-600 dark:text-stone-400 hover:bg-stone-200 dark:hover:bg-stone-800 active:bg-stone-300 dark:active:bg-stone-900"
            }
        )
    };

    view! {
        <div class="p-2 h-full text-left border-r border-stone-300 gap-[0.125rem] bg-stone-200/25 dark:border-stone-600 dark:bg-stone-800/25">
            <button
                class=button_class
                disabled=is_init
                on:click=move |_| {
                    let old_active_note_id = active_note_id.get_untracked();
                    create_new_note(list, active_note_id);

                    if let Some(old_active_note_id) = old_active_note_id {
                        let active_note = inputs_to_note(old_active_note_id, title_input, content_input);
                        post_note.dispatch((auth, active_note));
                    }

                    let title_node = title_input.get_untracked().unwrap();
                    title_node.set_value("");
                    title_input.get_untracked().unwrap().set_custom_validity("");
                    check_title_validity.notify();
                    content_input.get_untracked().unwrap().set_value("");
                    title_node.focus().unwrap();
                }
            >
                "New Note"
            </button>
            <div class="overflow-y-auto h-[calc(100dvh-16rem)]">
                <Transition>
                    {move || Suspend::new(async move {
                        let note = note_resource.await;

                        if let Some(note) = note {
                            list.update(|list| {
                                if let Some(title_signal) = list.get_mut(&note.id) {
                                    title_signal.set(note.title.clone());
                                };
                            });
                        }
                    })}
                </Transition>
                <ul class="flex flex-col-reverse w-[12rem] gap-[2px]">
                    <For
                        each=move || list.get()
                        key=|note| note.0
                        children=move |(id, title)| {
                            let is_active = move || {
                                if let Some(active_note_id) = active_note_id.get() {
                                    active_note_id == id
                                } else {
                                    false
                                }
                            };

                            view! {
                                <li>
                                    <button
                                        class="px-2 w-full text-sm text-left rounded py-[0.125rem] text-stone-700 truncate dark:text-stone-400 dark:hover:bg-stone-800 dark:active:bg-stone-900 hover:bg-stone-200 active:bg-stone-300"
                                        class:bg-stone-200=is_active
                                        class:dark:bg-stone-800=is_active
                                        on:click=move |_| {
                                            let old_active_note_id = active_note_id.get_untracked();
                                            if old_active_note_id != Some(id) {
                                                active_note_id.set(Some(id));

                                                if let Some(active_note_id) = old_active_note_id && note_resource.get_untracked().is_some() {
                                                    let active_note = inputs_to_note(active_note_id, title_input, content_input);
                                                    post_note.dispatch((auth, active_note));
                                                }

                                                title_input.get_untracked().unwrap().set_value(title.get_untracked().as_str());
                                                title_input.get_untracked().unwrap().set_custom_validity("");
                                                check_title_validity.notify();

                                                let content_node = content_input.get_untracked().unwrap();
                                                content_node.set_value("");
                                                content_node.focus().unwrap();
                                            }
                                        }
                                    >
                                        {
                                            move || {
                                                let title = title.get();
                                                if title.is_empty() {
                                                    Either::Left(
                                                        view! {
                                                            <span class="text-stone-400 dark:text-stone-600">"Untitled"</span>
                                                        }
                                                    )
                                                } else {
                                                    Either::Right(
                                                        title.to_string()
                                                    )
                                                }
                                            }
                                        }
                                    </button>
                                </li>
                            }
                        }
                    />
                </ul>
            </div>
        </div>
    }
}

#[component]
fn NoteEditor(
    list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>>,
    active_note_id: RwSignal<Option<NoteId>>,
    note_resource: Resource<Option<Note>>,
    post_note: PostNote,
    title_input: NodeRef<Input>,
    content_input: NodeRef<Textarea>,
    is_init: ReadSignal<bool>,
    check_title_validity: Trigger,
) -> impl IntoView {
    let auth = use_auth().unwrap();

    let readonly = move || note_resource.get().is_none() || post_note.pending().get();

    let is_title_invalid = Memo::new(move |_| {
        check_title_validity.track();
        title_input
            .get_untracked()
            .is_some_and(|node| !node.check_validity())
    });

    let submit_class = move || {
        format!(
            "btn btn-primary btn-sm px-6 {}",
            if is_title_invalid.get() {
                "bg-stone-300 dark:bg-stone-600 cursor-not-allowed"
            } else {
                "cursor-pointer"
            }
        )
    };

    view! {
        <div class="w-full h-full">
            <Transition
                fallback=move || {
                    view! {
                        <div
                            class="justify-center items-center w-full h-full flex pointer-events-none"
                        >
                            <p class="text-stone-500 dark:text-stone-400">
                                {
                                    move || {
                                        if is_init.get() {
                                            "Loading..."
                                        } else if list.get_untracked().is_empty() {
                                            "Press \"New Note\" to create a note"
                                        } else {
                                            "Select a note to start editing"
                                        }
                                    }
                                }
                            </p>
                        </div>}
                }>
                    {move || Suspend::new(async move {
                        let note = note_resource.await;

                        if let Some(note) = note {
                            title_input
                                .get()
                                .unwrap()
                                .set_value(note.title.to_string().as_str());
                            content_input
                                .get()
                                .unwrap()
                                .set_value(note.content.as_str());
                        }

                        view! {
                            <form
                                method="POST"
                                class="flex-col gap-2 w-full h-full flex"
                                on:submit=move |ev| {
                                    ev.prevent_default();
                                    if note_resource.get_untracked().is_some() {
                                        let active_note = inputs_to_note(active_note_id.get_untracked().unwrap(), title_input, content_input);
                                        post_note.dispatch((auth, active_note));
                                    }
                                }
                            >
                                <div class="flex items-center gap-2 p-2 border-b border-stone-300 dark:border-stone-600">
                                    <input
                                        class="p-2 w-full bg-transparent rounded outline-0 outline-red-500"
                                        style:outline-width=move || if is_title_invalid.get() { "2px" } else { "0" }
                                        node_ref=title_input
                                        type="text"
                                        readonly=readonly
                                        placeholder="Untitled"
                                        on:input=move |ev| {
                                            let input_value = event_target_value(&ev);
                                            let mut title = NoteTitle::new(input_value.clone());
                                            if title.is_ok() {
                                                title_input.get_untracked().unwrap().set_custom_validity("");
                                            } else {
                                                title_input.get_untracked().unwrap().set_custom_validity("Title is too long");
                                                title = NoteTitle::new(input_value.chars().take(50).collect::<String>());
                                            }
                                            list.update(|list| {
                                                if let Some(id) = active_note_id.get_untracked() && let Some(title_signal) = list.get_mut(&id) {
                                                    title_signal.set(title.unwrap());
                                                }
                                            });
                                            check_title_validity.notify();
                                        }
                                    />
                                    <div
                                        class="absolute px-2 ml-1 bg-red-500 rounded py-[0.125rem] mt-[-0.9rem]"
                                        style:display=move || if is_title_invalid.get() { "block" } else { "none" }
                                    >
                                        <p class="text-xs text-stone-100">"Title is up to 50 characters long"</p>
                                    </div>
                                    <input
                                        class=submit_class
                                        type="submit"
                                        disabled=readonly
                                        value="Save"
                                    />
                                </div>
                                <textarea
                                    node_ref=content_input
                                    readonly=readonly
                                    class="flex-grow py-2 px-4 w-full bg-transparent rounded resize-none outline-0"
                                ></textarea>
                            </form>}
                    })}
            </Transition>
        </div>
    }
}

fn create_new_note(
    list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>>,
    active_note_id: RwSignal<Option<NoteId>>,
) {
    let new_note_id = match list.get_untracked().keys().max() {
        Some(last_note_id) => last_note_id.increment(),
        None => NoteId::new(0),
    };

    list.update(|list| {
        list.insert(
            new_note_id,
            RwSignal::new(NoteTitle::new(String::new()).unwrap()),
        );
    });

    active_note_id.set(Some(new_note_id));
}

fn inputs_to_note(
    note_id: NoteId,
    title_input: NodeRef<Input>,
    content_input: NodeRef<Textarea>,
) -> Note {
    let title = title_input.get().unwrap().value().trim().to_string();
    let len = title.chars().count().min(50);
    let title = title.chars().take(len).collect::<String>();

    Note {
        id: note_id,
        title: NoteTitle::new(title).unwrap(),
        content: content_input.get().unwrap().value().trim().to_string(),
    }
}
