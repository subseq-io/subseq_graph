use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use subseq_auth::group_id::GroupId;
use subseq_auth::prelude::{AuthenticatedUser, ValidatesIdentity};

use crate::db;
use crate::error::{ErrorKind, LibError};
use crate::models::{
    CreateGraphPayload, GraphId, GroupGraphPermissions, ListGraphsQuery, Paged, UpdateGraphPayload,
    UpdateGroupGraphPermissionsPayload,
};
use crate::permissions;

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

pub trait GraphApp: HasPool + ValidatesIdentity {}

async fn create_graph_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateGraphPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::create_graph(
        &app.pool(),
        auth_user.id(),
        payload,
        permissions::graph_create_role(),
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
    let graphs = db::list_graphs(
        &app.pool(),
        auth_user.id(),
        page,
        limit,
        permissions::graph_read_role(),
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
    let graph = db::get_graph(
        &app.pool(),
        auth_user.id(),
        graph_id,
        permissions::graph_read_role(),
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
    let graph = db::update_graph(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        permissions::graph_update_role(),
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
    db::delete_graph(
        &app.pool(),
        auth_user.id(),
        graph_id,
        permissions::graph_delete_role(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn group_graph_permissions_get_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(group_id): Path<GroupId>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    db::authorize_group_permission(
        &app.pool(),
        auth_user.id(),
        group_id,
        permissions::graph_permissions_read_role(),
        "You do not have permission to view graph permissions for this group",
    )
    .await?;

    let allowed_roles = db::list_group_allowed_roles(&app.pool(), group_id).await?;
    Ok(Json(GroupGraphPermissions {
        group_id,
        allowed_roles,
    }))
}

async fn group_graph_permissions_put_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(group_id): Path<GroupId>,
    Json(payload): Json<UpdateGroupGraphPermissionsPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    db::authorize_group_permission(
        &app.pool(),
        auth_user.id(),
        group_id,
        permissions::graph_permissions_update_role(),
        "You do not have permission to manage graph permissions for this group",
    )
    .await?;

    db::set_group_allowed_roles(&app.pool(), group_id, &payload.allowed_roles).await?;
    let allowed_roles = db::list_group_allowed_roles(&app.pool(), group_id).await?;
    Ok(Json(GroupGraphPermissions {
        group_id,
        allowed_roles,
    }))
}

pub fn routes<S>() -> Router<S>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /graph [GET,POST]");
    tracing::info!("Registering route /graph/{{graph_id}} [GET,PUT,DELETE]");
    tracing::info!("Registering route /graph/group/{{group_id}}/permissions [GET,PUT]");

    Router::new()
        .route(
            "/graph",
            get(list_graphs_handler::<S>).post(create_graph_handler::<S>),
        )
        .route(
            "/graph/group/{group_id}/permissions",
            get(group_graph_permissions_get_handler::<S>)
                .put(group_graph_permissions_put_handler::<S>),
        )
        .route(
            "/graph/{graph_id}",
            get(get_graph_handler::<S>)
                .put(update_graph_handler::<S>)
                .delete(delete_graph_handler::<S>),
        )
}
