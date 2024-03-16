use synapsis::client::cmd_client;

fn main() {
    let client = reqwest::blocking::Client::new();
    cmd_client(&client);
}


