use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_web::middleware::Logger;
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::{Tera, Context};
//model
#[derive(Deserialize)]
struct AssignBugForm {
    bug_id: i32,
    developer_id: i32,
}
//handler

//to render the assign form
pub async fn get_assign_form(tmpl: web::Data<Tera>) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = tmpl.render("assign_form.html", &ctx).unwrap();
    HttpResponse::Ok().content_type("text/html").body(rendered)
}
//to handle the form submission
//will update the bug assigned developer in the database
pub async fn post_assign_bug(
    form: web::Form<AssignBugForm>,
    db_pool: web::Data<SqlitePool>,
    tmpl: web::Data<Tera>,
) -> impl Responder {
    let mut ctx = Context::new();
// Check if the bug and developer exist in the database
    let bug = sqlx::query!("SELECT bug_id FROM bugs WHERE bug_id = ?", form.bug_id)
        .fetch_optional(db_pool.get_ref())
        .await
        .unwrap();
// Check if the developer exists in the database
    let dev = sqlx::query!("SELECT developer_id FROM developers WHERE developer_id = ?", form.developer_id)
        .fetch_optional(db_pool.get_ref())
        .await
        .unwrap();
// If either the bug or developer does not exist, return an error
    if bug.is_none() || dev.is_none() {
        ctx.insert("error", "Invalid Bug ID or Developer ID");
        let rendered = tmpl.render("assign_error.html", &ctx).unwrap();
        return HttpResponse::BadRequest().content_type("text/html").body(rendered);
    }
//update the bug assigned to developer in the database
    sqlx::query!(
        "UPDATE bugs SET assigned_to = ? WHERE bug_id = ?",
        form.developer_id,
        form.bug_id
    )
    .execute(db_pool.get_ref())
    .await
    .unwrap();

    ctx.insert("bug_id", &form.bug_id);
    ctx.insert("developer_id", &form.developer_id);
    let rendered = tmpl.render("assign_success.html", &ctx).unwrap();
    HttpResponse::Ok().content_type("text/html").body(rendered)
}
//routes
HttpServer::new(move || {
    App::new()
        .wrap(Logger::default())
        .app_data(web::Data::new(pool.clone()))
        .app_data(web::Data::new(tera.clone()))
        .route("/bugs/assign", web::get().to(get_assign_form))
        .route("/bugs/assign", web::post().to(post_assign_bug))
})

