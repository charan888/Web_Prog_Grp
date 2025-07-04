use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct BugReport {
    pub title: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub developer_id: Option<i64>,
}

#[derive(Serialize)]
pub struct BugWithId {
    pub bug_id: i64,
    pub title: String,
    pub description: String,
    pub reported_by: String,
    pub severity: String,
    pub developer_id: Option<i64>,
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
    pub bug_id: i64,
    pub developer_id: i64,
}