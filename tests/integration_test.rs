#![feature(decl_macro)]

use core::time;
use std::{collections::HashMap, path::PathBuf, sync::{Arc, RwLock}, thread};

use ed25519_dalek::Signature;
use reqwest::blocking::Client;
use rocket::{config::Environment, http::Status, Config, State};
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use synapsis::{client::{delete_chat, delete_user, redact_chat, send_chat_message, Connection}, crypto::{gen_pub, gen_ver}, network::{from_username, MessageData, PutData, RegisterData, UserID, UserVerification}};

#[macro_use] extern crate rocket;

mod common;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
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

  fn reset(&mut self) {
    self.get = 0;
    self.put = 0;
    self.delete_user = 0;
    self.delete_path = 0;
    self.register = 0;
  }
}

const PROXY_PORT: u16 = 52569;
const ACTUAL_PORT: u16 = 52568;

fn base_addr() -> String {
  return format!("http://localhost:{}", ACTUAL_PORT);
}

fn proxy_addr() -> String {
  return format!("http://localhost:{}", PROXY_PORT);
}

/*
fn proxy() -> Result<reqwest::blocking::Client, reqwest::Error> {
  let target = Url::parse(&proxy_addr()).unwrap();

  let proxy = reqwest::Proxy::http(target).unwrap();
  
  reqwest::blocking::Client::builder()
    .proxy(proxy)
    .build()
}
*/

fn get_test_resource(name: String) -> Result<Value, String> {
  let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "resources", "test", &name[..]].iter().collect();
  let contents = std::fs::read_to_string(path)
    .map_err(|_| String::from("Failed to read file"))?;
  serde_json::from_str(&contents[..])
    .map_err(|_| String::from("Failed to deserialize file"))
}

#[derive(Serialize, Deserialize)]
struct UserData {
  username: String,
  password: String,
}

/*
#[derive(Serialize, Deserialize)]
struct FullUserData {
  username: String,
  user_id: UserID,
  password: String,
  pkp: Box<PublicKeyPair>,
  pkv: Box<VerifyKeyPair>,
  sk: Box<PrivateKey>,
}
*/

#[derive(Serialize, Deserialize)]
struct MessageDataSimple {
  from: String,
  to: String,
  message: String,
}

#[derive(Serialize, Deserialize)]
struct TestData {
  users: Vec<UserData>,
  messages: Vec<MessageDataSimple>,
}

fn get_test_data(name: String) -> Result<TestData, String> {
  let value = get_test_resource(name)?;
  let data: TestData = serde_json::from_value(value)
    .map_err(|_| "Failed to deserialize resource")?;
  Ok(data)
}

fn get_list_users(name: String) -> Result<Vec<String>, String> {
  let value = get_test_resource(name)?;
  let data: Vec<String> = serde_json::from_value(value)
    .map_err(|_| "Failed to deserialize resource")?;
  Ok(data)
}

fn get_list_user_pairs(name: String) -> Result<Vec<(String, String)>, String> {
  let value = get_test_resource(name)?;
  let data: Vec<(String, String)> = serde_json::from_value(value)
    .map_err(|_| "Failed to deserialize resource")?;
  Ok(data)
}

fn rocket() -> rocket::Rocket {
  let config = Config::build(Environment::Development)
    .address("localhost")
    .port(PROXY_PORT)
    .finalize()
    .unwrap();

  rocket::custom(config)
    .mount("/", routes![register, get, put, delete, delete_path, get_count, reset])
    .manage(Client::new())
    .manage(Arc::new(RwLock::new(RequestCounters::new())))
}

fn run() {
  rocket()
    .launch();
}

fn setup() {
  println!("Launching servers...");

  thread::spawn(move || {
    synapsis::server::run();
  });

  thread::spawn(move || {
    run();
  });

  std::thread::sleep(time::Duration::from_secs(1));
  println!("Assuming ready...");
}

#[test]
fn count_register() {
  //let client = proxy().unwrap();
  let client = Client::new();

  setup();

  let username = String::from("test_user");
  let password = String::from("password");
  let user_id = from_username(username.clone());
  let pkp = gen_pub(&username[..], &password[..]);
  let pkp = pkp.pubkey();
  let pkv = gen_ver(&username[..], &password[..]);
  let pkv = pkv.pubkey();

  let data = RegisterData {
    user_id,
    pkp,
    pkv,
  };

  client.post(format!("{}/register", proxy_addr()))
    .json(&data)
    .send()
    .and_then(|r| r.error_for_status())
    .expect("Failed to register");

  let res = client
    .get(format!("{}/count", proxy_addr()))
    .send()
    .and_then(|r| r.error_for_status())
    .expect("Failed to get counters");

  let ctrs: RequestCounters =
    serde_json::from_str(
      &res.text()
      .unwrap()
    )
      .expect("Failed to deserialize response");

  assert_eq!(ctrs, RequestCounters {
    register: 1,
    ..RequestCounters::new()
  });
}

#[test]
fn output_file() {
  let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "result", "test_output.json"].iter().collect();
  let _ = std::fs::create_dir_all(path.parent().unwrap());
  std::fs::write(path.clone(), serde_json::ser::to_string("This is a test.").expect("Failed to serialize")).expect("Failed to write file");
}

fn setup_from_test_input(client: Client, data: TestData, use_proxy: bool) -> HashMap<String, Box<Connection>> {
  let users = data.users;

  let address = if use_proxy { proxy_addr() } else { base_addr() };

  let conns: HashMap<String, Box<Connection>> = 
    users
      .iter()
      .map(|UserData { username, password }| 
        (username.clone(), Box::new(Connection::new(&client, &address, &username.clone(), &password.clone(), true).unwrap()))
      )
      .collect();

  let messages = data.messages;
  messages
    .iter()
    .for_each(|MessageDataSimple { from, to, message }| {
      let conn = conns.get(&from.clone()).unwrap();
      let data = MessageData {
        to: from_username(to.clone()),
        message: message.clone(),
      }.clone();
      send_chat_message(&conn, &data).expect("Failed to send message");
    });

  conns
}

/*
#[test]
fn test_ser() {
  panic!("{}",
    serde_json::ser::to_string(&TestData {
      users: vec![
        UserData {
          username: String::from("a"),
          password: String::from("b"),
        },
        UserData {
          username: String::from("c"),
          password: String::from("d"),
        },
      ],
      messages: vec![
        MessageDataSimple {
          from: String::from("a"),
          to: String::from("b"),
          message: String::from("x"),
        },
        MessageDataSimple {
          from: String::from("b"),
          to: String::from("a"),
          message: String::from("y"),
        },
      ],
    }).unwrap()
  );
}
*/

#[test]
fn count_setup_performance() {
  let client = Client::new();

  setup();

  let test_data = get_test_data(String::from("test_setup.json"))
    .expect("Failed to load test data");

  setup_from_test_input(client.clone(), test_data, true);

  let res =
    client
      .get(format!("{}/count", proxy_addr()))
      .send()
      .expect("Failed to get counter")
      .text()
      .expect("Failed to get counter");
  let count: RequestCounters = serde_json::from_str(&res).expect("Failed to deserialize response");

  let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "result", "setup_performance.json"].iter().collect();
  let _ = std::fs::create_dir_all(path.parent().unwrap());
  std::fs::write(path.clone(), serde_json::ser::to_string(&count).expect("Failed to serialize")).expect("Failed to write file");
}

#[test]
fn count_user_deletion_performance() {
  let client = Client::new();

  setup();

  let test_data = get_test_data(String::from("test_setup.json"))
    .expect("Failed to load test data");

  let conns = setup_from_test_input(client.clone(), test_data, true);

  client
    .post(format!("{}/reset", proxy_addr()))
    .send()
    .expect("Failed to reset counter");

  let delete_users = get_list_users(String::from("delete_users.json"))
    .expect("Failed to load test data");

  delete_users
    .iter()
    .for_each(|username| {
      delete_user(conns.get(username).unwrap()).unwrap();
    });

  let res =
    client
      .get(format!("{}/count", proxy_addr()))
      .send()
      .expect("Failed to get counter")
      .text()
      .expect("Failed to get counter");
  let count: RequestCounters = serde_json::from_str(&res).expect("Failed to deserialize response");

  let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "result", "user_deletion_performance.json"].iter().collect();
  let _ = std::fs::create_dir_all(path.parent().unwrap());
  std::fs::write(path.clone(), serde_json::ser::to_string(&count).expect("Failed to serialize")).expect("Failed to write file");
}

#[test]
fn count_chat_deletion_performance() {
  let client = Client::new();

  setup();

  let test_data = get_test_data(String::from("test_setup_2.json"))
    .expect("Failed to load test data");

  let conns = setup_from_test_input(client.clone(), test_data, true);

  client
    .post(format!("{}/reset", proxy_addr()))
    .send()
    .expect("Failed to reset counter");

  let delete_users = get_list_user_pairs(String::from("delete_chats.json"))
    .expect("Failed to load test data");

  delete_users
    .iter()
    .for_each(|(from, to)| {
      let _ = delete_chat(conns.get(from).unwrap(), conns.get(to).unwrap().user_id);
    });

  let res =
    client
      .get(format!("{}/count", proxy_addr()))
      .send()
      .expect("Failed to get counter")
      .text()
      .expect("Failed to get counter");
  let count: RequestCounters = serde_json::from_str(&res).expect("Failed to deserialize response");

  let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "result", "chat_deletion_performance.json"].iter().collect();
  let _ = std::fs::create_dir_all(path.parent().unwrap());
  std::fs::write(path.clone(), serde_json::ser::to_string(&count).expect("Failed to serialize")).expect("Failed to write file");
}

#[test]
fn count_chat_redaction_performance() {
  let client = Client::new();

  setup();

  let test_data = get_test_data(String::from("test_setup_2.json"))
    .expect("Failed to load test data");

  let conns = setup_from_test_input(client.clone(), test_data, true);

  client
    .post(format!("{}/reset", proxy_addr()))
    .send()
    .expect("Failed to reset counter");

  let redact_users = get_list_user_pairs(String::from("delete_chats.json"))
    .expect("Failed to load test data");

  redact_users
    .iter()
    .for_each(|(from, to)| {
      let _ = redact_chat(conns.get(from).unwrap(), conns.get(to).unwrap().user_id);
    });

  let res =
    client
      .get(format!("{}/count", proxy_addr()))
      .send()
      .expect("Failed to get counter")
      .text()
      .expect("Failed to get counter");
  let count: RequestCounters = serde_json::from_str(&res).expect("Failed to deserialize response");

  let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "result", "chat_redaction_performance.json"].iter().collect();
  let _ = std::fs::create_dir_all(path.parent().unwrap());
  std::fs::write(path.clone(), serde_json::ser::to_string(&count).expect("Failed to serialize")).expect("Failed to write file");
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

  //panic!("{:?}", res);

  res
    .map_err(translate_error)?
    .error_for_status()
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
      .error_for_status()
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
      .error_for_status()
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
      .error_for_status()
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
      .error_for_status()
      .map_err(translate_error)?
      .status();

  Ok(translate_status(status))
}

#[get("/count")]
fn get_count(ctr: State<Arc<RwLock<RequestCounters>>>) -> String {
  let ctr = *ctr.as_ref().read().expect("Failed to acquire lock");
  serde_json::ser::to_string(&ctr).unwrap()
}

#[post("/reset")]
fn reset(ctr: State<Arc<RwLock<RequestCounters>>>) -> () {
  ctr.write().unwrap().reset();
}

