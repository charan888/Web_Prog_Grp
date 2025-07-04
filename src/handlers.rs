
use actix_web::{HttpResponse, Responder, delete, get, post, put, web};
use bcrypt::{hash, verify};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use chrono::prelude::*;
use actix_web::{ App, HttpServer, middleware::Logger};
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use actix_web::web::Data;
use sha2::{Sha256, Digest};
use once_cell::sync::Lazy;
use tera::Tera;
use actix_web::{HttpRequest, Result};
use actix_web::web::Form;

use crate::models::{BugReport, BugWithId, ProjectPayload, LoginPayload, AssignForm};



static SALT: &str = "bugtrack";
static PROJECTS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/").route(web::get().to(homepage))) 
        .service(web::resource("/bugs/new").route(web::post().to(create_bug)))
        .service(web::resource("/projects").route(web::get().to(get_projects)))
        .service(web::resource("/projects").route(web::post().to(add_project)))
        .service(web::resource("/login").route(web::get().to(show_login_form))) 
        .service(web::resource("/login").route(web::post().to(login_form)))
        .service(web::resource("/api/login").route(web::post().to(login)))  
        .service(web::resource("/bugs/assign").route(web::post().to(show_assign_form)))
        .service(web::resource("/bugs/assign").route(web::post().to(assign_bug))); 
        
        
        
}

// === POST /bugs/new ===
async fn create_bug(
    pool: web::Data<SqlitePool>,
    bug: web::Json<BugReport>
) -> impl Responder {
    let result = sqlx::query(
        "INSERT INTO bugs (title, description, reported_by, severity, developer_id) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&bug.title)
    .bind(&bug.description)
    .bind(&bug.reported_by)
    .bind(&bug.severity)
    .bind(&bug.developer_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            let bug_id = res.last_insert_rowid();
            HttpResponse::Ok().json(BugWithId {
                bug_id,
                title: bug.title.clone(),
                description: bug.description.clone(),
                reported_by: bug.reported_by.clone(),
                severity: bug.severity.clone(),
                developer_id:  bug.developer_id.clone(),
            })
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

// === GET /projects ===
async fn get_projects() -> impl Responder {
    let list = PROJECTS.lock().unwrap();
    HttpResponse::Ok().json(&*list)
}

// === POST /projects (admin only) ===
async fn add_project(project: web::Json<ProjectPayload>) -> impl Responder {
    let mut list = PROJECTS.lock().unwrap();
    list.push(project.name.clone());
    HttpResponse::Ok().json(&*list)
}

// === POST /login ===
async fn login(payload: web::Json<LoginPayload>) -> impl Responder {
    // For demonstration: username = "admin", password = "password123"
    let correct_username = "admin";
    let correct_password_hash = hash_password("password123");

    if payload.username == correct_username && hash_password(&payload.password) == correct_password_hash {
        HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "token": "fake-session-token-123"
        }))
    } else {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "failure"
        }))
    }
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", SALT, password));
    format!("{:x}", hasher.finalize())
}
// GET /login (form page)
async fn show_login_form(tmpl: web::Data<Tera>) -> Result<HttpResponse> {
    let ctx = tera::Context::new();
    let rendered = tmpl.render("login.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

// POST /login (form submission)
async fn login_form(
    tmpl: web::Data<Tera>,
    form: web::Form<LoginPayload>
) -> Result<HttpResponse> {
    let correct_username = "admin";
    let correct_password_hash = hash_password("password123");

    if form.username == correct_username && hash_password(&form.password) == correct_password_hash {
        let mut ctx = tera::Context::new();
        ctx.insert("username", &form.username);
        let rendered = tmpl.render("assign.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
        Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
    } else {
        let mut ctx = tera::Context::new();
        ctx.insert("error", "Invalid username or password");
        let rendered = tmpl.render("login.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
        Ok(HttpResponse::Unauthorized().content_type("text/html").body(rendered))
    }
}

async fn show_assign_form(tmpl: web::Data<Tera>) -> Result<HttpResponse> {
    let rendered = tmpl.render("assign.html", &tera::Context::new())
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

async fn assign_bug(
    pool: web::Data<SqlitePool>,
    tmpl: web::Data<Tera>,
    form: Form<AssignForm>,
) -> Result<HttpResponse> {
    let result = sqlx::query("UPDATE bugs SET developer_id = ? WHERE id = ?")
        .bind(form.developer_id)
        .bind(form.bug_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(res) if res.rows_affected() == 1 => {
            let mut ctx = tera::Context::new();
            ctx.insert("bug_id", &form.bug_id);
            ctx.insert("developer_id", &form.developer_id);
            let rendered = tmpl.render("assign_success.html", &ctx)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        _ => Ok(HttpResponse::BadRequest().body("Invalid bug ID or developer ID")),
    }
}

async fn homepage(tmpl: web::Data<Tera>) -> Result<HttpResponse> {
    let rendered = tmpl.render("index.html", &tera::Context::new())
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}