use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::{SqlitePool};

#[derive(Serialize, Deserialize)]
pub struct BugReport {
    pub title: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub developer_id: Option<String>,
}



#[derive(Serialize,Deserialize)]
pub struct BugWithId {
    pub id: String,
    pub title: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub developer_id: Option<String>,
}

#[derive(Serialize,Deserialize)]
pub struct Developer {
    pub id: String,
    pub name: String,
    pub accessLevel: i64,
}

#[derive(Serialize,Deserialize)]
pub struct CreateDeveloper {
    pub name: String,
    pub accessLevel: i64,
}

#[derive(Serialize,Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub status: String,
    pub description: String,
}

#[derive(Serialize,Deserialize)]
pub struct CreateProject {
    pub name: String,
    pub status: String,
    pub description: String,
}


#[derive(Deserialize)]
pub struct ProjectPayload {
    pub name: String,
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct AssignForm {
    pub id: String,
    pub developer_id: String,
}

#[derive(Clone)]
pub struct MemoryDb(pub SqlitePool);