use candid::Principal;
use crate::stores::agent::{query_call, update_call};
use ic_cdk::api::call::CallResult;
use leptos::{*, html::{Input, Textarea}, leptos_dom::logging::console_log};
use shared::{util::canister_id::backend, Note, NoteId, NoteTitle};
use std::collections::BTreeMap;

type FetchNote = Action<(Option<Principal>, NoteId), (Result<Option<Note>, String>, NoteId)>;
type PostNote = Action<(Option<Principal>, NoteId, Note), ()>;

#[component]
pub fn NoteSection() -> impl IntoView {
    let (user_canister_id, set_user_canister_id) = create_signal(None);
    let list = RwSignal::new(BTreeMap::new());
    let active_note_id = RwSignal::new(None);
    let (is_init_loading, set_is_init_loading) = create_signal(true);

    let title_input = NodeRef::<Input>::new();
    let content_input = NodeRef::<Textarea>::new();

    let check_title_validity = Trigger::new();

    spawn_local(async move {
        let res: Option<Principal> = query_call(backend(), "get_user_canister_id", ()).await;

        match res {
            Some(canister_id) => {
                set_user_canister_id.set(Some(canister_id));
                let res: Vec<(NoteId, NoteTitle)> = query_call(canister_id, "get_note_id_and_title_vec", ()).await;
                let res = res.into_iter().map(|(note_id, title)| (note_id, RwSignal::new(title))).collect();
                list.set(res);
            },
            None =>{
                let res: CallResult<Principal> = update_call(backend(), "create_user_canister", ()).await;

                match res {
                    Ok(canister_id) => {
                        set_user_canister_id.set(Some(canister_id));
                    },
                    Err(e) => {
                        console_log(format!("Failed to create user canister: {:?}", e).as_str());
                    },
                }
            },
        }

        set_is_init_loading.set(false);
    });

    let fetch_note = Action::new(|input: &(Option<Principal>, NoteId)| {
        let (user_canister_id, note_id) = (input.0, input.1);
        async move {
            let res = fetch_note(&user_canister_id, &note_id).await;
            (res, note_id)
        }
    });

    Effect::new(move |_| {
        let res = fetch_note.value().get();

        if let Some((res, note_id)) = res {
            match res {
                Ok(note) => {
                    if let Some(note) = note {
                        list.update(|list| {
                            if let Some(title_signal) = list.get_mut(&note_id) {
                                title_signal.set(note.title.clone());
                            };
                        });
                        title_input.get().unwrap().set_value(note.title.to_string().as_str());
                        content_input.get().unwrap().set_value(note.content.as_str());

                        console_log(format!("Fetched note: {:?}", note).as_str());
                    }
                },
                Err(e) => {
                    console_log(format!("Failed to fetch note: {:?}", e).as_str());
                },
            }
        }
    });

    let post_note = Action::new(|input: &(Option<Principal>, NoteId, Note)| {
        let (user_canister_id, note_id, note) = (input.0, input.1, input.2.clone());
        async move {
            let res = post_note(&user_canister_id, &note_id, &note).await;

            if let Err(e) = res {
                console_log(format!("Failed to post note: {:?}", e).as_str());
            }
        }
    });

    view! {
        <section class="flex w-full h-full rounded-xl border border-stone-300 dark:border-stone-600">
            <NoteList user_canister_id list active_note_id fetch_note post_note title_input content_input is_init_loading check_title_validity />
            <NoteEditor user_canister_id list active_note_id fetch_note post_note title_input content_input is_init_loading check_title_validity />
        </section>
    }
}

#[component]
fn NoteList(user_canister_id: ReadSignal<Option<Principal>>, list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>>, active_note_id: RwSignal<Option<NoteId>>, fetch_note: FetchNote, post_note: PostNote, title_input: NodeRef<Input>, content_input: NodeRef<Textarea>, is_init_loading: ReadSignal<bool>, check_title_validity: Trigger) -> impl IntoView {
    let button_class = move || {
        format!("border rounded py-[0.125rem] px-4 mb-2 w-full {}",
            if is_init_loading.get() {
                "text-stone-500 dark:text-stone-600 bg-stone-200 dark:bg-stone-800"
            } else {
                "border-stone-300 text-stone-700 dark:border-stone-600 dark:text-stone-400 hover:bg-stone-200 dark:hover:bg-stone-800 active:bg-stone-300 dark:active:bg-stone-900"
            }
        )
    };

    view! {
        <div class="py-2 px-2 h-full text-left border-r border-stone-300 gap-[0.125rem] bg-stone-200/25 dark:border-stone-600 dark:bg-stone-800/25">
            <button
                class=button_class
                disabled=is_init_loading
                on:click=move |_| {
                    let old_active_note_id = active_note_id.get_untracked();
                    create_new_note(list, active_note_id);

                    if let Some(old_active_note_id) = old_active_note_id {
                        let active_note = inputs_to_note(title_input, content_input);
                        post_note.dispatch((user_canister_id.get_untracked(), old_active_note_id, active_note));
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

                                                let user_canister_id = user_canister_id.get_untracked();

                                                if let Some(active_note_id) = old_active_note_id {
                                                    if !fetch_note.pending().get_untracked() {
                                                        let active_note = inputs_to_note(title_input, content_input);
                                                        post_note.dispatch((user_canister_id, active_note_id, active_note));
                                                    }
                                                }
                                                fetch_note.dispatch((user_canister_id, id));

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
                                            move || if title.get().is_empty() {
                                                view! {
                                                    <span class="text-stone-400 dark:text-stone-600">"Untitled"</span>
                                                }.into_view()
                                            } else {
                                                title.into_view()
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
fn NoteEditor(user_canister_id: ReadSignal<Option<Principal>>, list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>>, active_note_id: RwSignal<Option<NoteId>>, fetch_note: FetchNote, post_note: PostNote, title_input: NodeRef<Input>, content_input: NodeRef<Textarea>, is_init_loading: ReadSignal<bool>, check_title_validity: Trigger) -> impl IntoView {
    let is_active = move || { active_note_id.get().is_some() };
    let readonly = move || { fetch_note.pending().get() || post_note.pending().get() };

    let is_title_invalid = Memo::new(move |_| {
        check_title_validity.track();
        title_input.get_untracked().map_or(false, |node| !node.check_validity())
    });

    let submit_class = move || {
        format!("text-stone-100 rounded py-1 px-6 {}",
            if is_title_invalid.get() {
                "bg-stone-300 dark:bg-stone-600 cursor-not-allowed"
            } else {
                "bg-blue-500 hover:bg-blue-600 active:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-700 dark:active:bg-blue-800 cursor-pointer"
            }
        )
    };

    view! {
        <div class="w-full h-full">
            <form
                class="flex-col gap-2 w-full h-full"
                style:display=move || if is_active() { "flex" } else { "none" }
                on:submit=move |ev| {
                    ev.prevent_default();
                    if !fetch_note.pending().get_untracked() {
                        let active_note = inputs_to_note(title_input, content_input);
                        post_note.dispatch((user_canister_id.get_untracked(), active_note_id.get_untracked().unwrap(), active_note));
                    }
                }
            >
                <div class="flex gap-2 p-2 border-b border-stone-300 dark:border-stone-600">
                    <input
                        label="Title"
                        class="p-2 w-full bg-transparent rounded outline-0 outline-red-500"
                        style:outline-width=move || if is_title_invalid.get() { "2px" } else { "0" }
                        ref=title_input
                        type="text"
                        readonly=readonly
                        invalid=is_title_invalid
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
                                if let Some(id) = active_note_id.get_untracked() {
                                    if let Some(title_signal) = list.get_mut(&id) {
                                        title_signal.set(title.unwrap());
                                    };
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
                    label="Content"
                    ref=content_input
                    readonly=readonly
                    class="flex-grow py-2 px-4 w-full bg-transparent rounded resize-none outline-0"
                ></textarea>
            </form>
            <div
                class="justify-center items-center w-full h-full pointer-events-none"
                style:display=move || if is_active() { "none" } else { "flex" }
            >
                <p class="text-stone-500 dark:text-stone-400">
                    {
                        move || {
                            if is_init_loading.get() {
                                "Loading..."
                            } else if list.get_untracked().is_empty() {
                                "Press \"New Note\" to create a note"
                            } else {
                                "Select a note to start editing"
                            }
                        }
                    }
                </p>
            </div>
        </div>
    }
}

fn create_new_note(list: RwSignal<BTreeMap<NoteId, RwSignal<NoteTitle>>>, active_note_id: RwSignal<Option<NoteId>>) {
    let new_note_id = match list.get_untracked().keys().max() {
        Some(last_note_id) => {
            last_note_id.increment()
        }
        None => {
            NoteId::new(0)
        }
    };

    list.update(|list| {
        list.insert(new_note_id, RwSignal::new(NoteTitle::new(String::new()).unwrap()));
    });

    active_note_id.set(Some(new_note_id));
}

async fn fetch_note(user_canister_id: &Option<Principal>, note_id: &NoteId) -> Result<Option<Note>, String> {
    match user_canister_id {
        Some(canister_id) => {
            let res: Option<Note> = query_call(*canister_id, "get_note", note_id).await;

            Ok(res)
        }
        None => {
            Err("user_canister_id is not set yet.".to_string())
        }
    }
}

async fn post_note(user_canister_id: &Option<Principal>, note_id: &NoteId, note: &Note) -> Result<(), String> {
    match user_canister_id {
        Some(canister_id) => {
            let old_note: Option<Note> = query_call(*canister_id, "get_note", note_id).await;

            if let Some(old_note) = old_note {
                if old_note == *note {
                    console_log("Note is unchanged.");
                    return Ok(()); // No need to save if the note is unchanged.
                }
            }

            console_log(format!("Posting note: {:?}", note).as_str());

            let _: () = update_call(*canister_id, "set_note", (note_id, note)).await;

            Ok(())
        }
        None => {
            Err("user_canister_id is not set yet.".to_string())
        }
    }
}

fn inputs_to_note(title_input: NodeRef<Input>, content_input: NodeRef<Textarea>) -> Note {
    let title = title_input.get().unwrap().value().trim().to_string();
    let len = title.chars().count().min(50);
    let title = title.chars().take(len).collect::<String>();

    Note {
        title: NoteTitle::new(title).unwrap(),
        content: content_input.get().unwrap().value().trim().to_string(),
    }
}
