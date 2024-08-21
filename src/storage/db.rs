// This file is currently not in use.

use idb::{
    Database, DatabaseEvent, Error, Factory, ObjectStoreParams, TransactionMode, TransactionResult,
};
use serde_json::Value;
use web_sys::wasm_bindgen::JsValue;

const AUTH_DB_NAME: &str = "auth-client-db";
const OBJECT_STORE_NAME: &str = "ic-keyval";

pub struct DbCreateOptions {
    pub db_name: Option<String>,
    pub store_name: Option<String>,
    pub version: Option<u32>,
}

#[derive(Debug)]
pub struct IdbKeyVal {
    db: Database,
    store_name: String,
}

impl IdbKeyVal {
    pub async fn new() -> Self {
        IdbKeyVal {
            db: create_database(AUTH_DB_NAME, OBJECT_STORE_NAME.to_string(), None)
                .await
                .unwrap(),
            store_name: OBJECT_STORE_NAME.to_string(),
        }
    }

    pub async fn new_with_options(options: DbCreateOptions) -> Self {
        let store_name = options
            .store_name
            .clone()
            .unwrap_or(OBJECT_STORE_NAME.to_string());

        IdbKeyVal {
            db: create_database(
                options.db_name.unwrap_or(AUTH_DB_NAME.to_string()),
                store_name,
                options.version,
            )
            .await
            .unwrap(),
            store_name: options.store_name.unwrap_or(OBJECT_STORE_NAME.to_string()),
        }
    }

    pub async fn get<T: AsRef<str>>(&self, key: T) -> Result<Option<Value>, Error> {
        get_value(&self.db, &self.store_name, JsValue::from(key.as_ref())).await
    }

    pub async fn set<S: AsRef<str>, T: Into<JsValue>>(
        &self,
        key: S,
        value: T,
    ) -> Result<TransactionResult, Error> {
        set_value(
            &self.db,
            &self.store_name,
            Some(&JsValue::from(key.as_ref())),
            value.into(),
        )
        .await
    }

    pub async fn remove<T: AsRef<str>>(&self, key: T) -> Result<TransactionResult, Error> {
        remove_value(&self.db, &self.store_name, JsValue::from(key.as_ref())).await
    }
}

async fn create_database<T: AsRef<str>>(
    db_name: T,
    store_name: String,
    version: Option<u32>,
) -> Result<Database, Error> {
    let factory = Factory::new()?;

    let mut open_request = factory.open(db_name.as_ref(), version).unwrap();

    open_request.on_upgrade_needed(move |event| {
        let database = event.database().unwrap();

        let store_names = database.store_names();
        if store_names.contains(&store_name) {
            database.delete_object_store(&store_name).unwrap();
        }

        database
            .create_object_store(&store_name, ObjectStoreParams::new())
            .unwrap();
    });

    open_request.await
}

async fn get_value<T: AsRef<str>>(
    database: &Database,
    store_name: T,
    key: JsValue,
) -> Result<Option<Value>, Error> {
    let transaction = database
        .transaction(&[store_name.as_ref()], TransactionMode::ReadOnly)
        .unwrap();

    let store = transaction.object_store(store_name.as_ref()).unwrap();

    let stored_value: Option<JsValue> = store.get(key)?.await?;

    let stored_value: Option<Value> =
        stored_value.map(|value| serde_wasm_bindgen::from_value(value).unwrap());

    transaction.await?;

    Ok(stored_value)
}

async fn set_value<T: AsRef<str>>(
    database: &Database,
    store_name: T,
    key: Option<&JsValue>,
    value: JsValue,
) -> Result<TransactionResult, Error> {
    let transaction = database
        .transaction(&[store_name.as_ref()], TransactionMode::ReadWrite)
        .unwrap();

    let store = transaction.object_store(store_name.as_ref()).unwrap();

    store.put(&value, key).unwrap();

    transaction.await
}

async fn remove_value<T: AsRef<str>>(
    database: &Database,
    store_name: T,
    key: JsValue,
) -> Result<TransactionResult, Error> {
    let transaction = database
        .transaction(&[store_name.as_ref()], TransactionMode::ReadWrite)
        .unwrap();

    let store = transaction.object_store(store_name.as_ref()).unwrap();

    store.delete(key).unwrap();

    transaction.await
}
