use actix_web::web::Data;
use benwis_leptos::telemetry::TracingSettings;
use cfg_if::cfg_if;

// boilerplate to run in different modes
cfg_if! {
if #[cfg(feature = "ssr")] {
    use actix_files::{Files};
    use actix_web::*;
    use actix_web::{cookie::Key, web, App, HttpServer, HttpResponse, Error};
    use actix_identity::IdentityMiddleware;
    use actix_session::{storage::CookieSessionStore, SessionMiddleware};

    use benwis_leptos::*;
    use benwis_leptos::telemetry::{get_subscriber, get_subscriber_with_tracing, init_subscriber};

    use leptos_actix::{generate_route_list, LeptosRoutes};
    use leptos::{log, view, get_configuration};
    use std::{ env};
    use sqlx::{sqlite::SqlitePoolOptions};
    use crate::app::*;

    // #[tracing::instrument(level = "info", fields(error))]
    // async fn server_fn_handler() -> actix_web::Route {

    //     leptos_actix::handle_server_fns_with_context( move |cx| {
    //         provide_context(cx, auth_session.clone());
    //         provide_context(cx, pool.clone());
    //     }).await
    // }

    // #[tracing::instrument(level = "info", fields(error))]
    // async fn leptos_routes_handler() -> actix_web::Route{
    //         let handler = leptos_actix::render_app_to_stream_with_context((*options).clone(),
    //         move |cx| {
    //             provide_context(cx, auth_session.clone());
    //             provide_context(cx, pool.clone());
    //         },
    //         |cx| view! { cx, <BenwisApp/> }
    //     );
    //     handler(req).await.into_response()
    // }

    #[actix_web::main]    
    async fn main() -> std::io::Result<()> {
        // Load .env file if one is present(should only happen in local dev)
        dotenvy::dotenv().ok();

        // simple_logger::init_with_level(log::Level::Info).expect("couldn't initialize logging");

        let pool = SqlitePoolOptions::new()
            .connect("sqlite:db/App.db")
            .await
            .expect("Could not make pool.");

        let parallelism = std::thread::available_parallelism().unwrap().get();
        log!("PARALLELISM: {parallelism}");

        let tracing_conf = TracingSettings{ 
            honeycomb_team: Some("6yem4uKpKZQBMObm755EdA".to_string()), 
            honeycomb_dataset: Some("benwis_leptos".to_string()), 
            honeycomb_service_name: Some("benwis_leptos".to_string()) 
        };

        // Get telemetry layer
        if env::var("LEPTOS_ENVIRONMENT").expect("Failed to find LEPTOS_ENVIRONMENT Env Var") == "local" {
            println!("LOCAL ENVIRONMENT");
            init_subscriber(get_subscriber(
                "benws_leptos".into(),
                "INFO".into(),
                std::io::stdout,
            ));
        } else {
            init_subscriber(
                get_subscriber_with_tracing(
                    "benwis_leptos".into(),
                    &tracing_conf,
                    "INFO".into(),
                    std::io::stdout,
                )
                .await,
            );
        }

        // The secret key would usually be read from a configuration file/environment variables.
        fn get_secret_key() -> Key {
            let session_secret = env::var("SESSION_SECRET").expect("SESSION_SECRET env var must be set!");
            // println!("SECRET: {:#?}", Key::generate());
            Key::from(session_secret.as_bytes())

        }
        let secret_key = get_secret_key();
          
        sqlx::migrate!()
            .run(&pool)
            .await
            .expect("could not run SQLx migrations");

        crate::functions::register_server_functions();

        // Setting this to None means we'll be using cargo-leptos and its env vars
        let conf = get_configuration(None).await.unwrap();
        let routes = generate_route_list(|cx| view! { cx, <BenwisApp/> });
        let addr = conf.leptos_options.site_addr.clone();

        // build our application with a route
        // let app = Router::new()
        // .route("/api/*fn_name", post(server_fn_handler))
        // .leptos_routes_with_handler(routes, get(leptos_routes_handler) )
        // .fallback(file_and_error_handler)
        // .layer(TraceLayer::new_for_http())
        // .layer(AuthSessionLayer::<User, i64, SessionSqlitePool, SqlitePool>::new(Some(pool.clone()))
        //     .with_config(auth_config))
        // .layer(SessionLayer::new(session_store))
        // .layer(Extension(Arc::new(leptos_options)))
        // .layer(Extension(pool))
        // .layer(CompressionLayer::new());

        // // run our app with hyper
        // // `axum::Server` is a re-export of `hyper::Server`
        // log!("listening on http://{}", &addr);
        // axum::Server::bind(&addr)
        //     .serve(app.into_make_service())
        //     .await
        //     .unwrap();

        HttpServer::new(move || {
            let leptos_options = &conf.leptos_options;
            let site_root = &leptos_options.site_root;
            let routes = &routes;


            App::new()
                // .service(css)
                .app_data(Data::new(pool.clone()))
                .route("/api/{tail:.*}", leptos_actix::handle_server_fns())
                .leptos_routes(leptos_options.to_owned(), routes.to_owned(), |cx| view! { cx, <BenwisApp/> })
                .service(Files::new("/", &site_root))
                .wrap(middleware::Compress::default())
                  // Install the identity framework first.
                .wrap(IdentityMiddleware::default())
                // The identity system is built on top of sessions. You must install the session
                // middleware to leverage `actix-identity`. The session middleware must be mounted
                // AFTER the identity middleware: `actix-web` invokes middleware in the OPPOSITE
                // order of registration when it receives an incoming request.
                .wrap(SessionMiddleware::new(CookieSessionStore::default(), secret_key.clone()))
        })
        .bind(addr)?
        .run()
        .await
    }
}

    // client-only stuff for Trunk
    else {
        pub fn main() {
            // This example cannot be built as a trunk standalone CSR-only app.
            // Only the server may directly connect to the database.
        }
    }
}
