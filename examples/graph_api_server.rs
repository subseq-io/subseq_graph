use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use subseq_auth::db::create_user_tables;
use subseq_auth::prelude::{
    AuthenticatedUser, ClaimsVerificationError, CoreIdToken, CoreIdTokenClaims, OidcToken, UserId,
    ValidatesIdentity,
};
use subseq_graph::api::{GraphApp, HasPool};
use uuid::Uuid;

const DEV_ID_TOKEN: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifQ.c2ln";

#[derive(Clone)]
struct DevAuthConfig {
    default_user_id: Uuid,
    default_username: String,
    default_email: String,
    require_dev_header: bool,
}

#[derive(Clone)]
struct ExampleApp {
    pool: Arc<PgPool>,
    auth: DevAuthConfig,
}

impl HasPool for ExampleApp {
    fn pool(&self) -> Arc<PgPool> {
        Arc::clone(&self.pool)
    }
}

impl GraphApp for ExampleApp {}

impl ValidatesIdentity for ExampleApp {
    fn validate_bearer(
        &self,
        _token: &str,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        Err(ClaimsVerificationError::Unsupported(
            "example server uses x-dev-user-id header auth".to_string(),
        ))
    }

    fn validate_token(
        &self,
        _token: &OidcToken,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        Err(ClaimsVerificationError::Unsupported(
            "example server does not validate OIDC sessions".to_string(),
        ))
    }

    fn refresh_token(
        &self,
        _token: OidcToken,
    ) -> impl std::future::Future<Output = anyhow::Result<OidcToken>> + Send {
        async {
            Err(anyhow!(
                "token refresh is unsupported in the example server"
            ))
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL is required to run examples/graph_api_server.rs")?;
    let bind = env::var("GRAPH_EXAMPLE_BIND").unwrap_or_else(|_| "127.0.0.1:4010".to_string());
    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid GRAPH_EXAMPLE_BIND '{}'", bind))?;

    let default_user_id = env::var("GRAPH_EXAMPLE_DEFAULT_USER_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".to_string());
    let default_user_id = Uuid::parse_str(&default_user_id).with_context(|| {
        format!(
            "invalid GRAPH_EXAMPLE_DEFAULT_USER_ID '{}'",
            default_user_id
        )
    })?;
    let auth = DevAuthConfig {
        default_user_id,
        default_username: env::var("GRAPH_EXAMPLE_DEFAULT_USERNAME")
            .unwrap_or_else(|_| "graph-example".to_string()),
        default_email: env::var("GRAPH_EXAMPLE_DEFAULT_EMAIL")
            .unwrap_or_else(|_| "graph-example@example.local".to_string()),
        require_dev_header: env_flag("GRAPH_EXAMPLE_REQUIRE_DEV_HEADER"),
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .context("failed to connect to postgres")?;

    create_user_tables(&pool)
        .await
        .context("failed to run auth migrations")?;
    subseq_graph::db::create_graph_tables(&pool)
        .await
        .context("failed to run graph migrations")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("failed to connect to postgres")?;

    let app_state = ExampleApp {
        pool: Arc::new(pool),
        auth,
    };

    let api_v1 = Router::new()
        .route("/healthz", get(health_handler))
        .route("/example/whoami", get(whoami_handler))
        .merge(subseq_graph::api::routes::<ExampleApp>());

    let app = Router::new()
        .nest("/api/v1", api_v1)
        .layer(from_fn_with_state(
            app_state.clone(),
            dev_identity_middleware,
        ))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind listener on {}", bind_addr))?;

    println!(
        "subseq_graph example server listening on http://{}",
        bind_addr
    );
    println!("api base path: /api/v1");
    println!("auth shim headers: x-dev-user-id, x-dev-email, x-dev-username");
    println!("set GRAPH_EXAMPLE_REQUIRE_DEV_HEADER=true to require x-dev-user-id");

    axum::serve(listener, app)
        .await
        .context("example server failed")
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        }
        Err(_) => false,
    }
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "ok": true
    }))
}

async fn whoami_handler(auth_user: AuthenticatedUser) -> Json<serde_json::Value> {
    Json(json!({
        "userId": auth_user.id().to_string(),
        "username": auth_user.username(),
    }))
}

async fn dev_identity_middleware(
    State(app): State<ExampleApp>,
    mut req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    let user_id = match parse_user_id(headers, &app.auth) {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let username = header_or_default(headers, "x-dev-username", &app.auth.default_username);
    let email = header_or_default(headers, "x-dev-email", &app.auth.default_email);

    let auth_user = match build_auth_user(user_id, &username, &email).await {
        Ok(user) => user,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, "invalid_dev_auth", &message),
    };

    req.extensions_mut().insert(auth_user);
    next.run(req).await
}

fn parse_user_id(headers: &HeaderMap, auth: &DevAuthConfig) -> Result<UserId, Response> {
    let Some(raw_user_id) = header_value(headers, "x-dev-user-id") else {
        if auth.require_dev_header {
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "missing_dev_user_id",
                "x-dev-user-id header is required",
            ));
        }
        return Ok(UserId(auth.default_user_id));
    };

    Uuid::parse_str(raw_user_id).map(UserId).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_dev_user_id",
            "invalid UUID",
        )
    })
}

fn header_or_default(headers: &HeaderMap, key: &str, default: &str) -> String {
    header_value(headers, key)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn header_value<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|value| value.to_str().ok())
}

async fn build_auth_user(
    user_id: UserId,
    username: &str,
    email: &str,
) -> Result<AuthenticatedUser, String> {
    let now = Utc::now().timestamp();
    let token = CoreIdToken::from_str(DEV_ID_TOKEN)
        .map_err(|_| "failed to parse built-in dev token".to_string())?;
    let claims: CoreIdTokenClaims = serde_json::from_value(json!({
        "iss": "https://subseq-graph-example.local",
        "sub": user_id.to_string(),
        "aud": ["subseq_graph_example"],
        "exp": now + 3600,
        "iat": now,
        "email": email,
        "preferred_username": username
    }))
    .map_err(|err| format!("failed to build claims: {}", err))?;

    AuthenticatedUser::from_claims(token, claims)
        .await
        .map_err(|err| format!("invalid dev auth user: {}", err))
}

fn json_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message
            }
        })),
    )
        .into_response()
}
