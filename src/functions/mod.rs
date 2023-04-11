#![allow(unused_variables)]
#![allow(unused_imports)]
pub mod auth;
pub mod dark_mode;
pub mod post;
pub mod user;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ssr")] {
        use sqlx::SqlitePool;
        use leptos::*;
        use actix_identity::{Identity, IdentityExt};
        use actix_web::HttpRequest;
        use actix_web::web::Data;

        pub fn pool(cx: Scope, req: &HttpRequest) -> Result<SqlitePool, ServerFnError> {
            let req = use_context::<actix_web::HttpRequest>(cx).expect("Failed to get Request");
            let pool = req.app_data::<Data<SqlitePool>>().expect("Failed to get Pool").get_ref().clone();
            Ok(pool)
        }

        pub fn identity(cx: Scope, req: &HttpRequest) -> Result<Identity, ServerFnError> {
            let req = use_context::<actix_web::HttpRequest>(cx).expect("Failed to get Request");
            IdentityExt::get_identity(&req)
            .map_err(|e| ServerFnError::ServerError(e.to_string()))

        }
        
        pub fn register_server_functions() {
            _ = post::AddPost::register();
            _ = post::GetPosts::register();
            _ = post::GetSomePosts::register();
            _ = post::GetSomePostsMeta::register();
            _ = post::GetPost::register();
            _ = post::UpdatePost::register();
            _ = post::DeletePost::register();
            _ = auth::Login::register();
            _ = auth::Logout::register();
            _ = auth::Signup::register();
            _ = user::GetUser::register();
            _ = user::GetSafeUser::register();
            _ = dark_mode::ToggleDarkMode::register();
        }
}}
