use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

#[derive(Serialize, Deserialize)]
pub struct BugReport {
    pub title: String,
    pub status: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub project: String,
    pub developer_id: Option<String>,
}

pub struct BugReportComplete {
    pub title: String,
    pub status: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub project: String,
    pub developer_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct BugUpdate {
    pub status: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub reported_by: Option<String>,
    pub severity: Option<String>,
    pub project: Option<String>,
    pub developer_id: Option<String>,
}




#[derive(Serialize,Deserialize)]
pub struct BugWithId {
    pub id: String,
    pub title: String,
    pub status: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub project: String,
    pub developer_id: Option<String>,
}

#[derive(Serialize,Deserialize)]
pub struct BugFilter {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub project: Option<String>,
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

