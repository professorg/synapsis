use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct RegisterData {
    pub username: String,
    pub pkp: String,
    pub pkv: String,
}

