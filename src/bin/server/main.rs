#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    path::PathBuf,
    process,
    fs,
};
use ed25519_dalek::Signature;
use rocket::{
    http::Status,
    State,
};
use rocket_contrib::json::Json;
use synapsis::{
    crypto::{vrfy, VerifyKeyPair},
    network::{PutData, RegisterData, UserVerification},
};
use serde_json::Value;

type Username = String;
type StorageInner = HashMap<Username, Arc<RwLock<HashMap<String, Value>>>>;
type Storage = Arc<RwLock<StorageInner>>;

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

fn delete_user(storage: &Storage, user: String) -> Result<Status, Status> {
  if let Ok(mut storage) = storage.write() {
    storage.remove(&user);
    Ok(Status::Ok)
  } else {
    Err(Status::InternalServerError)
  }
}

fn delete_data(storage: &Storage, user: String, path: String) -> Result<Status, Status> {
  if let Ok(storage) = storage.read() {
    if let Some(inner) = storage.get(&user) {
      if let Ok(mut inner) = inner.write() {
        inner.remove(&path);
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

fn put_data(storage: &Storage, user: String, path: String, data: Value) -> Result<Status, Status> {
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

fn get_data(storage: &Storage, user: String, path: String) -> Result<Value, Status> {
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
    let res = get_data(storage.inner(), user, path);
    res
      .and_then(|x|
        serde_json::ser::to_string(&x)
          .map_err(|_| Status::InternalServerError))
}

#[put("/<user>/<path..>", format = "application/json", data = "<data>")]
fn put(storage: State<Storage>, user: String, path: PathBuf, data: Json<PutData>) -> Result<Status, Status> {
    let path = path.to_str().ok_or(Status::InternalServerError)?.to_string();
    let pk = get_data(storage.inner(), user.clone(), "pkv".to_string())?;
    let pk: VerifyKeyPair = serde_json::from_value(pk)
        .map_err(|_| Status::InternalServerError)?;
    let data_str = serde_json::ser::to_string(&data.data).map_err(|_| Status::InternalServerError)?;
    if vrfy(data_str.as_bytes(), data.signature, &pk) {
        put_data(storage.inner(), user.clone(), path, data.data.clone())
    } else {
        Err(Status::Unauthorized)
    }
}

#[delete("/<user>", format = "application/json", data = "<data>")]
fn delete(storage: State<Storage>, user: String, data: Json<UserVerification>) -> Result<Status, Status> {
  let pk = get_data(storage.inner(), user.clone(), "pkv".to_string())?;
  let pk: VerifyKeyPair = serde_json::from_value(pk)
    .map_err(|_| Status::InternalServerError)?;
  let nonce = &data.nonce;
  let nonce_str =
    serde_json::ser::to_string(&nonce)
    .map_err(|_| Status::InternalServerError)?;
  let nonce_bytes = nonce_str.as_bytes();
  let signature = data.signature;
  if vrfy(&nonce_bytes, signature, &pk) {
    delete_user(&storage, user)
  } else {
    Err(Status::Unauthorized)
  }
}

#[delete("/<user>/<path..>", format = "application/json", data = "<signature>")]
fn delete_path(storage: State<Storage>, user: String, path: PathBuf, signature: Json<Signature>) -> Result<Status, Status> {
  let pk = get_data(storage.inner(), user.clone(), "pkv".to_string())?;
  let pk: VerifyKeyPair = serde_json::from_value(pk)
    .map_err(|_| Status::InternalServerError)?;
  let path = path.to_str().ok_or(Status::InternalServerError)?.to_string();
  let path_bytes = path.as_bytes();
  if vrfy(&path_bytes, signature.0, &pk) {
    delete_data(&storage, user, path)
  } else {
    Err(Status::Unauthorized)
  }
}

#[post("/register", format = "application/json", data = "<data>")]
fn register(storage: State<Storage>, data: Json<RegisterData>) -> Result<Status, Status> {
    let storage = storage.inner();
    let pkp = serde_json::value::to_value(&data.pkp)
        .map_err(|_| Status::InternalServerError)?;
    let pkv = serde_json::value::to_value(&data.pkv)
        .map_err(|_| Status::InternalServerError)?;
    make_user(storage, data.username.clone())
        .and(put_data(storage, data.username.clone(), "pkp".to_string(), pkp))
        .and(put_data(storage, data.username.clone(), "pkv".to_string(), pkv))
}

fn rocket() -> rocket::Rocket {
    let storage = storage();
    let ctrlc_storage = storage.clone();

    //TODO: impl Drop for the storage
    ctrlc::set_handler(move || {
        fs::write("database.json", serde_json::ser::to_string(&ctrlc_storage).unwrap()).unwrap();
        process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    rocket::ignite()
        .mount("/", routes![register, get, put, delete, delete_path])
        .manage(storage)
}

fn storage() -> Storage {
    fs::read_to_string("database.json").ok()
        .and_then(|db| serde_json::from_str::<Storage>(&db[..]).ok())
        .unwrap_or_default()
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
        assert_eq!(put_data(&storage, username.to_string(), path.to_string(), serde_json::json!(data)), Ok(Status::Ok));
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
        assert_eq!(put_data(&storage, username.to_string(), path.to_string(), serde_json::json!(data)), Err(Status::NotFound));
    }

    #[test]
    fn storage_get_data() {
        let storage = storage();
        let username = "testuser";
        let path = "some/path";
        let data = "some_data";
        assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(put_data(&storage, username.to_string(), path.to_string(), serde_json::json!(data)), Ok(Status::Ok));
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

