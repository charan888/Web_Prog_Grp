use crate::auth::{create_token, validate_token};
use crate::middleware::Authorization;
use actix_web::web::Form;
use actix_web::{HttpResponse, Responder, Result, delete, get, post, put, web};
use bcrypt::{hash, verify};
use chrono::prelude::*;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Row, Sqlite, SqlitePool};
use std::sync::Mutex;
use tera::Tera;
use uuid::Uuid;

use crate::models::{
    AssignForm, BugReport, BugWithId, CreateDeveloper, CreateProject, Developer, LoginPayload,
    Project, MemoryDb
};

static SALT: &str = "bugtrack";
static PROJECTS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/").route(web::get().to(homepage)))
        .service(web::resource("/bugs").route(web::get().to(get_bugs)))
        .service(
            web::resource("/bugs/assign")
                .route(web::post().to(assign_bug))
                .route(web::get().to(show_assign_form)),
        )
        .service(web::resource("/bugs/new").route(web::post().to(create_bug)))
        .service(
            web::resource("/bugs/{id}")
                .route(web::get().to(get_bugs_id))
                .route(web::delete().to(delete_bugs_id))
                .route(web::patch().to(update_bug)),
        )
        .service(web::resource("/developers/new").route(web::post().to(create_developer)))
        .service(
            web::resource("/projects")
                .route(web::get().to(get_projects))
                .route(web::post().to(add_project).wrap(Authorization)),
        )
        .service(
            web::resource("/page/login")
                .route(web::get().to(show_login_form))
                .route(web::post().to(login_form)),
        )
        .service(web::resource("/login").route(web::post().to(login)));
}

// === POST /bugs/new ===
async fn create_bug(pool: web::Data<SqlitePool>, bug: web::Json<BugReport>) -> impl Responder {
    let id = Uuid::new_v4().to_string();
    let result = sqlx::query(
        "INSERT INTO bugs (id,title, description, reported_by, severity, developer_id) VALUES (?,?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&bug.title)
    .bind(&bug.description)
    .bind(&bug.reported_by)
    .bind(&bug.severity)
    .bind(&bug.developer_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => HttpResponse::Ok().json(BugWithId {
            id: id,
            title: bug.title.clone(),
            description: bug.description.clone(),
            reported_by: bug.reported_by.clone(),
            severity: bug.severity.clone(),
            developer_id: bug.developer_id.clone(),
        }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

// === GET /projects ===
async fn get_projects(pool: web::Data<MemoryDb>) -> impl Responder {
    let res = sqlx::query("SELECT * FROM projects")
        .fetch_all(&pool.0)
        .await;

    match res {
        Ok(res) => {
            let bugs: Vec<Project> = res
                .into_iter()
                .map(|r| Project {
                    id: r.get("id"),
                    name: r.get("name"),
                    description: r.get("description"),
                    status: r.get("status"),
                })
                .collect();

            if bugs.len() == 0 {
                return HttpResponse::NotFound().json("No bugs in the system");
            }
            HttpResponse::Ok().json(bugs)
        }
        Err(e) => {
            eprintln!("Failed to fetch stock prices: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch stock prices")
        }
    }
}

// === POST /projects (admin only) ===
async fn add_project(
    pool: web::Data<MemoryDb>,
    project: web::Json<CreateProject>,
) -> impl Responder {
    let id = Uuid::new_v4().to_string();
    let result =
        sqlx::query("INSERT INTO projects (id,name, description, status) VALUES (?,?, ?, ?)")
            .bind(&id)
            .bind(&project.name)
            .bind(&project.description)
            .bind(&project.status)
            .execute(&pool.0)
            .await;

    match result {
        Ok(res) => HttpResponse::Ok().json(Project {
            id: id,
            name: project.name.clone(),
            description: project.description.clone(),
            status: project.status.clone(),
        }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

// === POST /login ===
async fn login(payload: web::Json<LoginPayload>) -> impl Responder {
    // For demonstration: username = "admin", password = "password123"
    let correct_username = "admin";
    let correct_password_hash = hash_password("password123");

    if payload.username == correct_username
        && hash_password(&payload.password) == correct_password_hash
    {
        let token = create_token(Uuid::new_v4());
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "token": token
        }));
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
    let rendered = tmpl
        .render("login.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

// POST /login (form submission)
async fn login_form(tmpl: web::Data<Tera>, form: web::Form<LoginPayload>) -> Result<HttpResponse> {
    let correct_username = "admin";
    let correct_password_hash = hash_password("password123");

    if form.username == correct_username && hash_password(&form.password) == correct_password_hash {
        let mut ctx = tera::Context::new();
        ctx.insert("username", &form.username);
        let rendered = tmpl
            .render("assign.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
        Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
    } else {
        let mut ctx = tera::Context::new();
        ctx.insert("error", "Invalid username or password");
        let rendered = tmpl
            .render("login.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
        Ok(HttpResponse::Unauthorized()
            .content_type("text/html")
            .body(rendered))
    }
}

async fn show_assign_form(tmpl: web::Data<Tera>) -> Result<HttpResponse> {
    let rendered = tmpl
        .render("assign.html", &tera::Context::new())
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

async fn assign_bug(
    pool: web::Data<SqlitePool>,
    tmpl: web::Data<Tera>,
    form: Form<AssignForm>,
) -> Result<HttpResponse> {
    let result = sqlx::query("UPDATE bugs SET developer_id = ? WHERE id = ?")
        .bind(form.developer_id.clone())
        .bind(form.id.clone())
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(res) if res.rows_affected() == 1 => {
            let mut ctx = tera::Context::new();
            ctx.insert("bug_id", &form.id);
            ctx.insert("developer_id", &form.developer_id);
            ctx.insert("success", "Bug assigned successfully!");
            let rendered = tmpl
                .render("assign.html", &ctx)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        _ => {
            let mut ctx = tera::Context::new();
            ctx.insert("error", "Invalid Bug ID or Developer ID");
            ctx.insert("bug_id", &form.id);
            ctx.insert("developer_id", &form.developer_id);
            let rendered = tmpl
                .render("assign.html", &ctx)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
    }
}

async fn homepage(tmpl: web::Data<Tera>) -> Result<HttpResponse> {
    let rendered = tmpl
        .render("index.html", &tera::Context::new())
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

async fn get_bugs(pool: web::Data<SqlitePool>) -> impl Responder {
    let res = sqlx::query("SELECT * FROM bugs")
        .fetch_all(pool.get_ref())
        .await;

    match res {
        Ok(res) => {
            let bugs: Vec<BugWithId> = res
                .into_iter()
                .map(|r| BugWithId {
                    id: r.get("id"),
                    title: r.get("title"),
                    description: r.get("description"),
                    reported_by: r.get("reported_by"),
                    severity: r.get("severity"),
                    developer_id: r.get("developer_id"),
                })
                .collect();

            if bugs.len() == 0 {
                return HttpResponse::NotFound().json("No bugs in the system");
            }
            HttpResponse::Ok().json(bugs)
        }
        Err(e) => {
            eprintln!("Failed to fetch stock prices: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch stock prices")
        }
    }
}

async fn get_bugs_id(pool: web::Data<SqlitePool>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    let res = sqlx::query("SELECT * FROM bugs WHERE id = ?")
        .bind(id)
        .fetch_all(pool.get_ref())
        .await;

    match res {
        Ok(res) => {
            let bugs: Vec<BugWithId> = res
                .into_iter()
                .map(|r| BugWithId {
                    id: r.get("id"),
                    title: r.get("title"),
                    description: r.get("description"),
                    reported_by: r.get("reported_by"),
                    severity: r.get("severity"),
                    developer_id: r.get("developer_id"),
                })
                .collect();

            if bugs.len() == 0 {
                return HttpResponse::NotFound().json("No bug found");
            }
            HttpResponse::Ok().json(bugs)
        }
        Err(e) => {
            eprintln!("Failed to fetch stock prices: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch stock prices")
        }
    }
}

async fn delete_bugs_id(pool: web::Data<SqlitePool>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    let res = sqlx::query("DELETE FROM bugs WHERE id = ?")
        .bind(id)
        .execute(pool.get_ref())
        .await;

    match res {
        Ok(res) => {
            if res.rows_affected() == 0 {
                return HttpResponse::NotFound().json("No bug updated");
            }

            HttpResponse::Ok().json("Bug is deleted")
        }
        Err(e) => {
            eprintln!("Failed to fetch stock prices: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch stock prices")
        }
    }
}

async fn update_bug(
    pool: web::Data<SqlitePool>,
    bug: web::Json<BugWithId>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner().to_string();
    println!("{}", id);
    let result = sqlx::query(
        "UPDATE bugs SET  title = ?, description = ?, reported_by = ?, severity = ?, developer_id = ? WHERE id =?"
    )
    .bind(&bug.title)
    .bind(&bug.description)
    .bind(&bug.reported_by)
    .bind(&bug.severity)
    .bind(&bug.developer_id)
    .bind(&id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                return HttpResponse::NotFound().json("No bug updated");
            }

            HttpResponse::Ok().json(BugWithId {
                id: id,
                title: bug.title.clone(),
                description: bug.description.clone(),
                reported_by: bug.reported_by.clone(),
                severity: bug.severity.clone(),
                developer_id: bug.developer_id.clone(),
            })
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

async fn create_developer(
    pool: web::Data<SqlitePool>,
    bug: web::Json<CreateDeveloper>,
) -> impl Responder {
    let id = Uuid::new_v4().to_string();
    let result = sqlx::query("INSERT INTO developers (id,name, accessLevel ) VALUES ( ?, ?, ?)")
        .bind(&id)
        .bind(&bug.name)
        .bind(&bug.accessLevel)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(res) => HttpResponse::Ok().json(Developer {
            id: id,
            name: bug.name.clone(),
            accessLevel: bug.accessLevel.clone(),
        }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}
