use actix_web::{web, App, HttpServer, Responder, HttpResponse, middleware::Logger};
use serde::{Serialize, Deserialize};
use sqlx::{SqlitePool};
use std::sync::Mutex;
use actix_web::web::Data;
use sha2::{Sha256, Digest};
use once_cell::sync::Lazy;
use tera::Tera;
use actix_web::{HttpRequest, Result};
use actix_web::web::Form;

#[derive(Deserialize)]
struct AssignForm {
    bug_id: i64,
    developer_id: i64,
}


static SALT: &str = "bugtrack";
static PROJECTS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[derive(Serialize, Deserialize)]
struct BugReport {
    title: String,
    description: String,
    reported_by: String,
    severity: String,
    developer_id: Option<i64>,
}

#[derive(Serialize)]
struct BugWithId {
    bug_id: i64,
    title: String,
    description: String,
    reported_by: String,
    severity: String,
    developer_id: Option<i64>,
}

#[derive(Deserialize)]
struct ProjectPayload {
    name: String,
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    //std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let db_pool = SqlitePool::connect("sqlite://bugs.db?mode=rwc")
    .await
    .expect("Failed to connect to DB");

    let tera = Tera::new("templates/**/*").expect("Failed to initialize Tera");

    // Ensure table exists
    sqlx::query("
        CREATE TABLE IF NOT EXISTS bugs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            reported_by TEXT NOT NULL,
            severity TEXT NOT NULL,
            developer_id INTEGER
        )
    ").execute(&db_pool).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db_pool.clone()))
            .app_data(Data::new(tera.clone()))
            .wrap(Logger::default())
            .route("/", web::get().to(homepage))
            .route("/bugs/new", web::post().to(create_bug))
            .route("/projects", web::get().to(get_projects))
            .route("/projects", web::post().to(add_project))
            .route("/login", web::get().to(show_login_form))  // HTML form
            .route("/login", web::post().to(login_form))      // HTML form submission
            .route("/api/login", web::post().to(login))       // JSON API login
            .route("/bugs/assign", web::get().to(show_assign_form))
            .route("/bugs/assign", web::post().to(assign_bug))

    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
