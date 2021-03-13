#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    path::PathBuf,
};
use rocket::{
    http::Status,
    State,
};
use rocket_contrib::json::Json;
use synapsis::{
    crypto::{VerifyKeyPair, vrfy},
    network::{RegisterData, PutData},
};

type StorageInner = HashMap<String, Arc<RwLock<HashMap<String, String>>>>;
type Storage = RwLock<StorageInner>;


fn make_user(storage: &Storage, user: String) -> Result<Status, Status> {
    if let Ok(mut storage) = storage.write() {
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

fn put_data(storage: &Storage, user: String, path: String, data: String) -> Result<Status, Status> {
    if let Ok(storage) = storage.read() {
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

fn get_data(storage: &Storage, user: String, path: String) -> Result<String, Status> {
    if let Ok(storage) = storage.read() {
        if let Some(inner) = storage.get(&user) {
            if let Ok(inner) = inner.read() {
                if let Some(data) = inner.get(&path) {
                    Ok(data.clone())
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

#[get("/<user>/<path..>")]
fn get(storage: State<Storage>, user: String, path: PathBuf) -> Result<String, Status> {
    let path = path.to_str().ok_or(Status::InternalServerError)?.to_string();
    get_data(storage.inner(), user, path)
}

#[put("/<user>/<path..>", format = "application/json", data = "<data>")]
fn put(storage: State<Storage>, user: String, path: PathBuf, data: Json<PutData>) -> Result<Status, Status> {
    let path = path.to_str().ok_or(Status::InternalServerError)?.to_string();
    let pk = get_data(storage.inner(), user.clone(), "pkv".to_string())?;
    let pk: VerifyKeyPair = serde_json::from_str(&pk[..])
        .map_err(|_| Status::InternalServerError)?;
    if vrfy(&data.data.as_bytes(), data.signature, &pk) {
        put_data(storage.inner(), user.clone(), path, data.data.clone())
    } else {
        Err(Status::Unauthorized)
    }
}

#[post("/register", format = "application/json", data = "<data>")]
fn register(storage: State<Storage>, data: Json<RegisterData>) -> Result<Status, Status> {
    let storage = storage.inner();
    let pkp = serde_json::ser::to_string(&data.pkp)
        .map_err(|_| Status::InternalServerError)?;
    let pkv = serde_json::ser::to_string(&data.pkv)
        .map_err(|_| Status::InternalServerError)?;
    make_user(storage, data.username.clone())
        .and(put_data(storage, data.username.clone(), "pkp".to_string(), pkp))
        .and(put_data(storage, data.username.clone(), "pkv".to_string(), pkv))
}

fn rocket() -> rocket::Rocket {
    rocket::ignite()
        .mount("/", routes![register, get, put])
        .manage(storage())
}

fn storage() -> Storage {
    RwLock::new(StorageInner::new())
}

fn main() {
    rocket()
        .launch();
}

#[cfg(test)]
mod test {
    use crate::{
        rocket,
        storage,
        make_user,
        put_data,
        get_data,
    };
    use rocket::http::Status;

    #[test]
    fn storage_make_user() {
        let storage = storage();
        let username = "testuser";
        assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert!(
            storage
                .read().unwrap()
                .get(&username.to_string())
                .is_some()
        );
    }

    #[test]
    fn storage_make_user_conflict() {
        let storage = storage();
        let username = "testuser";
        assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(make_user(&storage, username.to_string()), Err(Status::Conflict));
    }

    #[test]
    fn storage_put_data() {
        let storage = storage();
        let username = "testuser";
        let path = "some/path";
        let data = "some_data";
        assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(put_data(&storage, username.to_string(), path.to_string(), data.to_string()), Ok(Status::Ok));
        assert_eq!(
            *storage
                .read().unwrap()
                .get(&username.to_string()).unwrap()
                .read().unwrap()
                .get(&path.to_string()).unwrap(),
            data
        );
    }

    #[test]
    fn storage_put_data_not_found() {
        let storage = storage();
        let username = "testuser";
        let path = "some/path";
        let data = "some_data";
        // Do not create the account
        // assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(put_data(&storage, username.to_string(), path.to_string(), data.to_string()), Err(Status::NotFound));
    }

    #[test]
    fn storage_get_data() {
        let storage = storage();
        let username = "testuser";
        let path = "some/path";
        let data = "some_data";
        assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(put_data(&storage, username.to_string(), path.to_string(), data.to_string()), Ok(Status::Ok));
        assert_eq!(get_data(&storage, username.to_string(), path.to_string()).unwrap(), data.to_string());
    }

    #[test]
    fn storage_get_data_user_not_found() {
        let storage = storage();
        let username = "testuser";
        let path = "some/path";
        assert_eq!(get_data(&storage, username.to_string(), path.to_string()), Err(Status::NotFound));
    }

    #[test]
    fn storage_get_data_path_not_found() {
        let storage = storage();
        let username = "testuser";
        let path = "some/path";
        assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(get_data(&storage, username.to_string(), path.to_string()), Err(Status::NotFound));
    }

}

