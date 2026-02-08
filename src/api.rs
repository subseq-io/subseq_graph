use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use subseq_auth::prelude::{AuthenticatedUser, ValidatesIdentity};

use crate::db;
use crate::error::{ErrorKind, LibError};
use crate::models::{CreateGraphPayload, GraphId, ListGraphsQuery, Paged, UpdateGraphPayload};

#[derive(Debug)]
pub struct AppError(pub LibError);

impl From<LibError> for AppError {
    fn from(value: LibError) -> Self {
        Self(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self.0.kind {
            ErrorKind::Database => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        };

        tracing::error!(kind = ?self.0.kind, error = %self.0.source, "graph api request failed");
        (status, self.0.public).into_response()
    }
}

pub trait HasPool {
    fn pool(&self) -> Arc<sqlx::PgPool>;
}

pub trait GraphApp: HasPool + ValidatesIdentity {
    fn allowed_group_roles(&self) -> Option<Vec<String>> {
        None
    }
}

async fn create_graph_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateGraphPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let allowed_roles = app.allowed_group_roles();
    let graph = db::create_graph_with_roles(
        &app.pool(),
        auth_user.id(),
        payload,
        allowed_roles.as_deref(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(graph)))
}

async fn list_graphs_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Query(query): Query<ListGraphsQuery>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let (page, limit) = query.pagination();
    let allowed_roles = app.allowed_group_roles();
    let graphs = db::list_graphs_with_roles(
        &app.pool(),
        auth_user.id(),
        page,
        limit,
        allowed_roles.as_deref(),
    )
    .await?;
    Ok(Json(Paged {
        page,
        limit,
        items: graphs,
    }))
}

async fn get_graph_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let allowed_roles = app.allowed_group_roles();
    let graph = db::get_graph_with_roles(
        &app.pool(),
        auth_user.id(),
        graph_id,
        allowed_roles.as_deref(),
    )
    .await?;
    Ok(Json(graph))
}

async fn update_graph_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<UpdateGraphPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let allowed_roles = app.allowed_group_roles();
    let graph = db::update_graph_with_roles(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        allowed_roles.as_deref(),
    )
    .await?;
    Ok(Json(graph))
}

async fn delete_graph_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let allowed_roles = app.allowed_group_roles();
    db::delete_graph_with_roles(
        &app.pool(),
        auth_user.id(),
        graph_id,
        allowed_roles.as_deref(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes<S>() -> Router<S>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /graph [GET,POST]");
    tracing::info!("Registering route /graph/{{graph_id}} [GET,PUT,DELETE]");

    Router::new()
        .route(
            "/graph",
            get(list_graphs_handler::<S>).post(create_graph_handler::<S>),
        )
        .route(
            "/graph/{graph_id}",
            get(get_graph_handler::<S>)
                .put(update_graph_handler::<S>)
                .delete(delete_graph_handler::<S>),
        )
}
