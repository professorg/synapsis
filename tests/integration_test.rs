#![feature(decl_macro)]

use std::{path::PathBuf, sync::{Arc, RwLock}};

use ed25519_dalek::Signature;
use reqwest::blocking::Client;
use rocket::{http::Status, State};
use rocket_contrib::json::Json;
use synapsis::network::{PutData, RegisterData, UserID, UserVerification};

#[macro_use] extern crate rocket;

mod common;

struct RequestCounters {
  get: usize,
  put: usize,
  delete_user: usize,
  delete_path: usize,
  register: usize,
}

impl RequestCounters {
  fn new() -> Self {
    RequestCounters {
      get: 0,
      put: 0,
      delete_user: 0,
      delete_path: 0,
      register: 0,
    }
  }
}

const PROXY_PORT: usize = 52569;
const ACTUAL_PORT: usize = 52568;

fn proxy() -> Result<reqwest::Client, reqwest::Error>{
    reqwest::Client::builder()
      .proxy(reqwest::Proxy::http(format!("http://localhost:{}", PROXY_PORT))?)
      .build()
}

fn rocket() -> rocket::Rocket {
  rocket::ignite()
    .mount("/", routes![register, get, put, delete, delete_path])
    .manage(proxy().unwrap())
    .manage(Arc::new(RequestCounters::new()))
}

fn run() {
  rocket()
    .launch();
}

#[test]
fn it_works() {
  let client = proxy().unwrap();
  unimplemented!()
}

fn base_addr() -> String {
  return format!("http://localhost:{}", ACTUAL_PORT);
}

fn translate_status(status: reqwest::StatusCode) -> Status {
  let code = status.as_u16();
  Status::from_code(code).unwrap_or(Status::NotImplemented)
}

fn translate_error(err: reqwest::Error) -> Status {
  let code = err.status().unwrap_or_default().as_u16();
  Status::from_code(code).unwrap_or(Status::NotImplemented)
}

#[get("/<user>/<path..>")]
fn get(client: State<Client>, ctr: State<Arc<RwLock<RequestCounters>>>, user: UserID, path: PathBuf) -> Result<String, Status> {
  ctr.write().unwrap().get += 1;
  let res =
    client
      .get(format!("{}/{}/{}", base_addr(), user, path.to_string_lossy()))
      .send();

  res
    .map_err(translate_error)?
    .text()
    .map_err(translate_error)
}

#[put("/<user>/<path..>", format = "application/json", data = "<data>")]
fn put(client: State<Client>, ctr: State<Arc<RwLock<RequestCounters>>>, user: UserID, path: PathBuf, data: Json<PutData>) -> Result<Status, Status> {
  ctr.write().unwrap().put += 1;
  let res = 
    client.put(format!("{}/{}/{}", base_addr(), user, path.to_string_lossy()))
      .json(&data.0)
      .send();

  let status =
    res
      .map_err(translate_error)?
      .status();

  Ok(translate_status(status))
}

#[delete("/<user>", format = "application/json", data = "<data>")]
fn delete(client: State<Client>, ctr: State<Arc<RwLock<RequestCounters>>>, user: UserID, data: Json<UserVerification>) -> Result<Status, Status> {
  ctr.write().unwrap().delete_user += 1;
  let res = 
    client.delete(format!("{}/{}", base_addr(), user))
      .json(&data.0)
      .send();

  let status =
    res
      .map_err(translate_error)?
      .status();

  Ok(translate_status(status))
}

#[delete("/<user>/<path..>", format = "application/json", data = "<signature>")]
fn delete_path(client: State<Client>, ctr: State<Arc<RwLock<RequestCounters>>>, user: UserID, path: PathBuf, signature: Json<Signature>) -> Result<Status, Status> {
  ctr.write().unwrap().delete_path += 1;
  let res = 
    client.delete(format!("{}/{}/{}", base_addr(), user, path.to_string_lossy()))
      .json(&signature.0)
      .send();

  let status =
    res
      .map_err(translate_error)?
      .status();

  Ok(translate_status(status))
}

#[post("/register", format = "application/json", data = "<data>")]
fn register(client: State<Client>, ctr: State<Arc<RwLock<RequestCounters>>>, data: Json<RegisterData>) -> Result<Status, Status> {
  ctr.write().unwrap().register += 1;
  let res = 
    client.post(format!("{}/register", base_addr()))
      .json(&data.0)
      .send();

  let status =
    res
      .map_err(translate_error)?
      .status();

  Ok(translate_status(status))
}


