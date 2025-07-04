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
use dotenvy::dotenv;

mod handlers;
mod models;
mod auth;
mod middleware;

use crate::models::MemoryDb;



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    //std::env::set_var("RUST_LOG", "debug");

     dotenv().ok();

    env_logger::init();

    let db_pool = SqlitePool::connect("sqlite://bugs.db?mode=rwc")
    .await
    .expect("Failed to connect to DB");

    let memory_pool = SqlitePool::connect("sqlite::memory:")
    .await
    .expect("Failed to connect to DB");

    let tera = Tera::new("templates/**/*").expect("Failed to initialize Tera");

    // Ensure table exists
    sqlx::query("
        CREATE TABLE IF NOT EXISTS bugs (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            reported_by TEXT NOT NULL,
            severity TEXT NOT NULL,
            developer_id TEXT,
            FOREIGN KEY (developer_id) REFERENCES developers(id)
        )
    ").execute(&memory_pool).await.unwrap();

    sqlx::query("
        CREATE TABLE IF NOT EXISTS developers (
            id TEXT PRIMARY KEY ,
            name VARCHAR(100) NOT NULL,
            accessLevel INTEGER NOT NULL
        )
    ").execute(&db_pool).await.unwrap();

    sqlx::query("
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY ,
            name VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            description TEXT
        )
    ").execute(&db_pool).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db_pool.clone()))
            .app_data(Data::new(MemoryDb(db_pool.clone())))
            .app_data(Data::new(tera.clone()))
            .wrap(Logger::default())
            .configure(handlers::config)

    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
