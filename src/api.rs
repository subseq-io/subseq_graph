use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use subseq_auth::group_id::GroupId;
use subseq_auth::prelude::{AuthenticatedUser, ValidatesIdentity, structured_error_response};

use crate::db;
use crate::error::{ErrorKind, LibError};
use crate::models::{
    AddEdgePayload, CreateGraphPayload, EdgeMutationCheckResponse, EdgeMutationPayload, GraphId,
    GraphNodeId, GroupGraphPermissions, GuardedUpdateGraphPayload, ListGraphsQuery,
    MetadataFilterPayload, Paged, RemoveEdgePayload, RemoveNodePayload, UpdateGraphPayload,
    UpdateGroupGraphPermissionsPayload, UpsertEdgeMetadataPayload, UpsertNodePayload,
    ValidateGraphEdgesPayload, ValidateGraphEdgesResponse,
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
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::Database => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        };
        tracing::error!(kind = ?self.0.kind, error = %self.0.source, "graph api request failed");
        structured_error_response(status, self.0.code, self.0.public, self.0.details)
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
        permissions::graph_create_access_roles(),
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
        permissions::graph_read_access_roles(),
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
        permissions::graph_read_access_roles(),
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
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn guarded_replace_graph_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<GuardedUpdateGraphPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::update_graph_with_guard(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload.graph,
        payload.expected_updated_at,
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn upsert_node_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<UpsertNodePayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::upsert_node(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn remove_node_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<RemoveNodePayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::remove_node(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn add_edge_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<AddEdgePayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::add_edge(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn remove_edge_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<RemoveEdgePayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::remove_edge(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn upsert_edge_metadata_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<UpsertEdgeMetadataPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::upsert_edge_metadata(
        &app.pool(),
        auth_user.id(),
        graph_id,
        payload,
        permissions::graph_update_access_roles(),
    )
    .await?;
    Ok(Json(graph))
}

async fn node_by_external_id_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path((graph_id, external_id)): Path<(GraphId, String)>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let node = db::find_node_by_external_id(
        &app.pool(),
        auth_user.id(),
        graph_id,
        &external_id,
        permissions::graph_read_access_roles(),
    )
    .await?;

    match node {
        Some(node) => Ok(Json(node).into_response()),
        None => Err(AppError(LibError::not_found(
            "Node not found",
            anyhow::anyhow!(
                "external id '{}' not found in graph {}",
                external_id,
                graph_id
            ),
        ))),
    }
}

async fn incident_edges_for_node_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path((graph_id, node_id)): Path<(GraphId, GraphNodeId)>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let edges = db::list_incident_edges_for_node(
        &app.pool(),
        auth_user.id(),
        graph_id,
        node_id,
        permissions::graph_read_access_roles(),
    )
    .await?;
    Ok(Json(edges))
}

async fn incident_edges_for_external_id_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path((graph_id, external_id)): Path<(GraphId, String)>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let edges = db::list_incident_edges_for_external_id(
        &app.pool(),
        auth_user.id(),
        graph_id,
        &external_id,
        permissions::graph_read_access_roles(),
    )
    .await?;
    Ok(Json(edges))
}

async fn query_nodes_metadata_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<MetadataFilterPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let nodes = db::list_graph_nodes_by_metadata(
        &app.pool(),
        auth_user.id(),
        graph_id,
        &payload.metadata_contains,
        permissions::graph_read_access_roles(),
    )
    .await?;
    Ok(Json(nodes))
}

async fn query_edges_metadata_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<MetadataFilterPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let edges = db::list_graph_edges_by_metadata(
        &app.pool(),
        auth_user.id(),
        graph_id,
        &payload.metadata_contains,
        permissions::graph_read_access_roles(),
    )
    .await?;
    Ok(Json(edges))
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
        permissions::graph_delete_access_roles(),
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
        permissions::graph_permissions_read_access_roles(),
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
        permissions::graph_permissions_update_access_roles(),
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

async fn validate_graph_edges_handler<S>(
    State(_app): State<S>,
    _auth_user: AuthenticatedUser,
    Json(payload): Json<ValidateGraphEdgesPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let normalized = payload.normalize()?;
    let violations = crate::invariants::graph_invariant_violations(
        normalized.kind,
        &normalized.nodes,
        &normalized.edges,
    );
    Ok(Json(ValidateGraphEdgesResponse {
        valid: violations.is_empty(),
        violations,
    }))
}

async fn validate_add_edge_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<EdgeMutationPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::get_graph(
        &app.pool(),
        auth_user.id(),
        graph_id,
        permissions::graph_update_access_roles(),
    )
    .await?;
    let index = crate::invariants::GraphMutationIndex::new(graph.kind, &graph.nodes, &graph.edges);
    let violations = index.would_add_edge_violations(payload.from_node_id, payload.to_node_id);
    Ok(Json(EdgeMutationCheckResponse {
        valid: violations.is_empty(),
        would_introduce_violation: !violations.is_empty(),
        would_isolate_subgraph: false,
        violations,
    }))
}

async fn validate_remove_edge_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(graph_id): Path<GraphId>,
    Json(payload): Json<EdgeMutationPayload>,
) -> Result<impl IntoResponse, AppError>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    let graph = db::get_graph(
        &app.pool(),
        auth_user.id(),
        graph_id,
        permissions::graph_update_access_roles(),
    )
    .await?;
    let index = crate::invariants::GraphMutationIndex::new(graph.kind, &graph.nodes, &graph.edges);
    let violations = index.would_remove_edge_violations(payload.from_node_id, payload.to_node_id);
    let would_isolate_subgraph =
        index.would_remove_edge_isolate_subgraph(payload.from_node_id, payload.to_node_id);
    Ok(Json(EdgeMutationCheckResponse {
        valid: violations.is_empty(),
        would_introduce_violation: !violations.is_empty(),
        would_isolate_subgraph,
        violations,
    }))
}

pub fn routes<S>() -> Router<S>
where
    S: GraphApp + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /graph [GET,POST]");
    tracing::info!("Registering route /graph/validate [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/replace [PUT]");
    tracing::info!("Registering route /graph/{{graph_id}}/node/upsert [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/node/remove [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/edge/add [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/edge/remove [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/edge/upsert-metadata [POST]");
    tracing::info!(
        "Registering route /graph/{{graph_id}}/node/by-external-id/{{external_id}} [GET]"
    );
    tracing::info!("Registering route /graph/{{graph_id}}/edge/incident/node/{{node_id}} [GET]");
    tracing::info!(
        "Registering route /graph/{{graph_id}}/edge/incident/external-id/{{external_id}} [GET]"
    );
    tracing::info!("Registering route /graph/{{graph_id}}/nodes/query-metadata [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/edges/query-metadata [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/validate/add-edge [POST]");
    tracing::info!("Registering route /graph/{{graph_id}}/validate/remove-edge [POST]");
    tracing::info!("Registering route /graph/{{graph_id}} [GET,PUT,DELETE]");
    tracing::info!("Registering route /graph/group/{{group_id}}/permissions [GET,PUT]");

    Router::new()
        .route("/graph/validate", post(validate_graph_edges_handler::<S>))
        .route(
            "/graph/{graph_id}/replace",
            put(guarded_replace_graph_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/node/upsert",
            post(upsert_node_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/node/remove",
            post(remove_node_handler::<S>),
        )
        .route("/graph/{graph_id}/edge/add", post(add_edge_handler::<S>))
        .route(
            "/graph/{graph_id}/edge/remove",
            post(remove_edge_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/edge/upsert-metadata",
            post(upsert_edge_metadata_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/node/by-external-id/{external_id}",
            get(node_by_external_id_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/edge/incident/node/{node_id}",
            get(incident_edges_for_node_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/edge/incident/external-id/{external_id}",
            get(incident_edges_for_external_id_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/nodes/query-metadata",
            post(query_nodes_metadata_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/edges/query-metadata",
            post(query_edges_metadata_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/validate/add-edge",
            post(validate_add_edge_handler::<S>),
        )
        .route(
            "/graph/{graph_id}/validate/remove-edge",
            post(validate_remove_edge_handler::<S>),
        )
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
