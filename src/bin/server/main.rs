#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use serde::{Serialize, Deserialize};
use rocket::{
    http::Status,
    State,
};
use rocket_contrib::json::Json;

#[derive(Serialize, Deserialize)]
struct RegisterData {
    username: String,
    pkp: String,
    pkv: String,
}

type StorageInner = HashMap<String, Arc<RwLock<HashMap<String, String>>>>;
type Storage = RwLock<StorageInner>;

type Response<T> = Result<Json<T>, Status>;


fn make_user(storage: &State<Storage>, user: String) -> Result<Status, Status> {
    if let Ok(mut storage) = storage.inner().write() {
        if storage.contains_key(&user) {
            Err(Status::Conflict)
        } else {
            storage.insert(user.clone(), Arc::new(RwLock::new(HashMap::new())));
            Ok(Status::Ok)
        }
    } else {
        Err(Status::InternalServerError)
    }
}

fn put_data(storage: &State<Storage>, user: String, path: String, data: String) -> Result<Status, Status> {
    if let Ok(storage) = storage.inner().read() {
        if let Some(inner) = storage.get(&user) {
            if let Ok(mut inner) = inner.write() {
                inner.insert(path, data);
                Ok(Status::Ok)
            } else {
                Err(Status::InternalServerError)
            }
        } else {
            Err(Status::NotFound)
        }
    } else {
        Err(Status::InternalServerError)
    }
}

fn get_data(storage: &State<Storage>, user: String, path: String) -> Response<String> {
    if let Ok(storage) = storage.inner().read() {
        if let Some(inner) = storage.get(&user) {
            if let Ok(inner) = inner.read() {
                if let Some(data) = inner.get(&path) {
                    Ok(Json(data.clone()))
                } else {
                    Err(Status::NotFound)
                }
            } else {
                Err(Status::InternalServerError)
            }
        } else {
            Err(Status::NotFound)
        }
    } else {
        Err(Status::InternalServerError)
    }
}

#[get("/<user>/<path>")]
fn get(storage: State<Storage>, user: String, path: String) -> Response<String> {
    get_data(&storage, user, path)
}

#[post("/register", format = "application/json", data = "<data>")]
fn register(storage: State<Storage>, data: Json<RegisterData>) -> Status {
    make_user(&storage, data.username.clone())
        .and(put_data(&storage, data.username.clone(), "pkp".to_string(), data.pkp.clone()))
        .and(put_data(&storage, data.username.clone(), "pkv".to_string(), data.pkv.clone()))
        .map_or_else(|o| o, |e| e)
}

fn main() {
    rocket::ignite()
        .mount("/", routes![register, get])
        .manage(RwLock::new(StorageInner::new()))
        .launch();
}
