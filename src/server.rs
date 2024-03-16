use std::{
    collections::HashMap, fs, panic, path::PathBuf, process::exit, sync::{Arc, RwLock}
};
use ed25519_dalek::Signature;
use rocket::{
    http::Status,
    State,
};
use rocket_contrib::json::Json;
use crate::{
    crypto::{vrfy, VerifyKeyPair},
    network::{PutData, RegisterData, UserID, UserVerification},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use derive_more::{Deref, DerefMut};

type Storage = Arc<RwLock<StorageInner>>;

#[derive(Default, Serialize, Deserialize, Deref, DerefMut)]
struct StorageInner(HashMap<UserID, RwLock<HashMap<String, Value>>>);

const STORAGE_FILENAME: &str = "database.json";

impl StorageInner {
  fn write_to_fs(&self) {
    println!("Saving storage to {}...", STORAGE_FILENAME);
    fs::write(STORAGE_FILENAME, serde_json::ser::to_string(&self).unwrap()).unwrap();
    println!("Saved.");
  }
}

fn make_user(storage: &Storage, user: UserID) -> Result<Status, Status> {
  let mut storage =
    storage
      .write()
      .map_err(|_| Status::InternalServerError)?;
  if storage.contains_key(&user) {
    Err(Status::Conflict)
  } else {
    storage.insert(user, RwLock::new(HashMap::new()));
    Ok(Status::Ok)
  }
}

fn delete_user(storage: &Storage, user: UserID) -> Result<Status, Status> {
  storage
    .write()
    .map_err(|_| Status::InternalServerError)?
    .remove(&user)
    .ok_or(Status::InternalServerError)?;
  Ok(Status::Ok)
}

fn delete_data(storage: &Storage, user: UserID, path: String) -> Result<Status, Status> {
  storage
    .read()
    .map_err(|_| Status::InternalServerError)?
    .get(&user)
    .ok_or(Status::NotFound)?
    .write()
    .map_err(|_| Status::InternalServerError)?
    .remove(&path)
    .ok_or(Status::NotFound)?;
  Ok(Status::Ok)
}

fn put_data(storage: &Storage, user: UserID, path: String, data: Value) -> Result<Status, Status> {
  storage
    .read()
    .map_err(|_| Status::InternalServerError)?
    .get(&user)
    .ok_or(Status::NotFound)?
    .write()
    .map_err(|_| Status::InternalServerError)?
    .insert(path, data);
  Ok(Status::Ok)
}

fn get_data(storage: &Storage, user: UserID, path: String) -> Result<Value, Status> {
  storage
    .read()
    .map_err(|_| Status::InternalServerError)?
    .get(&user)
    .ok_or(Status::NotFound)?
    .read()
    .map_err(|_| Status::InternalServerError)?
    .get(&path)
    .map(Value::clone)
    .ok_or(Status::NotFound)
}

#[get("/<user>/<path..>")]
fn get(storage: State<Storage>, user: UserID, path: PathBuf) -> Result<String, Status> {
    let path = path.to_str().ok_or(Status::InternalServerError)?.to_string();
    let res = get_data(storage.inner(), user, path);
    res
      .and_then(|x|
        serde_json::ser::to_string(&x)
          .map_err(|_| Status::InternalServerError))
}

#[put("/<user>/<path..>", format = "application/json", data = "<data>")]
fn put(storage: State<Storage>, user: UserID, path: PathBuf, data: Json<PutData>) -> Result<Status, Status> {
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
fn delete(storage: State<Storage>, user: UserID, data: Json<UserVerification>) -> Result<Status, Status> {
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
fn delete_path(storage: State<Storage>, user: UserID, path: PathBuf, signature: Json<Signature>) -> Result<Status, Status> {
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
    make_user(storage, data.user_id)
        .and(put_data(storage, data.user_id, "pkp".to_string(), pkp))
        .and(put_data(storage, data.user_id, "pkv".to_string(), pkv))
}

fn rocket(storage: Storage) -> rocket::Rocket {
    rocket::ignite()
        .mount("/", routes![register, get, put, delete, delete_path])
        .manage(storage)
}

fn storage() -> Storage {
    fs::read_to_string(STORAGE_FILENAME).ok()
        .and_then(|db| serde_json::from_str::<Storage>(&db[..]).ok())
        .unwrap_or_default()
}

pub fn run() {
    let storage = storage();
    let storage_ref_ctrlc = storage.clone();
    let storage_ref_unwind = storage.clone();

    ctrlc::set_handler(move || {
      println!("Exiting...");
      storage_ref_ctrlc
        .read()
        .unwrap()
        .write_to_fs();
      exit(0)
    }).expect("Failed to set ctrlc handler.");

    panic::catch_unwind(|| {
      rocket(storage)
          .launch();
    })
    .unwrap_or_else(move |err| {
      storage_ref_unwind
        .read()
        .unwrap()
        .write_to_fs();
      panic::resume_unwind(err)
    })
}

#[cfg(test)]
mod test {
    use crate::server::{
        Storage,
        make_user,
        put_data,
        get_data,
    };
    use rocket::http::Status;
    use crate::network::from_username;

    #[test]
    fn storage_make_user() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        assert_eq!(make_user(&storage, user_id), Ok(Status::Ok));
        assert!(
            storage
                .read().unwrap()
                .get(&user_id)
                .is_some()
        );
    }

    #[test]
    fn storage_make_user_conflict() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        assert_eq!(make_user(&storage, user_id), Ok(Status::Ok));
        assert_eq!(make_user(&storage, user_id), Err(Status::Conflict));
    }

    #[test]
    fn storage_put_data() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        let path = "some/path";
        let data = "some_data";
        assert_eq!(make_user(&storage, user_id), Ok(Status::Ok));
        assert_eq!(put_data(&storage, user_id, path.to_string(), serde_json::json!(data)), Ok(Status::Ok));
        assert_eq!(
            *storage
                .read().unwrap()
                .get(&user_id).unwrap()
                .read().unwrap()
                .get(&path.to_string()).unwrap(),
            data
        );
    }

    #[test]
    fn storage_put_data_not_found() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        let path = "some/path";
        let data = "some_data";
        // Do not create the account
        // assert_eq!(make_user(&storage, username.to_string()), Ok(Status::Ok));
        assert_eq!(put_data(&storage, user_id, path.to_string(), serde_json::json!(data)), Err(Status::NotFound));
    }

    #[test]
    fn storage_get_data() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        let path = "some/path";
        let data = "some_data";
        assert_eq!(make_user(&storage, user_id), Ok(Status::Ok));
        assert_eq!(put_data(&storage, user_id, path.to_string(), serde_json::json!(data)), Ok(Status::Ok));
        assert_eq!(get_data(&storage, user_id, path.to_string()).unwrap(), data.to_string());
    }

    #[test]
    fn storage_get_data_user_not_found() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        let path = "some/path";
        assert_eq!(get_data(&storage, user_id, path.to_string()), Err(Status::NotFound));
    }

    #[test]
    fn storage_get_data_path_not_found() {
        let storage = Storage::default();
        let username = "testuser".to_string();
        let user_id = from_username(username);
        let path = "some/path";
        assert_eq!(make_user(&storage, user_id), Ok(Status::Ok));
        assert_eq!(get_data(&storage, user_id, path.to_string()), Err(Status::NotFound));
    }

}

