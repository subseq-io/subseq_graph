use std::collections::HashSet;

use anyhow::anyhow;
use chrono::NaiveDateTime;
use once_cell::sync::Lazy;
use serde_json::Value;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use subseq_auth::group_id::GroupId;
use subseq_auth::user_id::UserId;

use crate::error::{LibError, Result};
use crate::models::{
    AddEdgePayload, CreateGraphPayload, DirectedGraph, GraphDefinition, GraphDeltaCommand,
    GraphDeltaOperation, GraphEdge, GraphId, GraphKind, GraphNode, GraphNodeId, GraphSummary,
    RemoveEdgePayload, RemoveNodePayload, ReparentNodePayload, UpdateGraphPayload,
    UpsertEdgeMetadataPayload, UpsertNodePayload, api_metadata_to_db_json, db_metadata_to_api_json,
    normalize_api_metadata,
};
use crate::permissions;

pub static MIGRATOR: Lazy<Migrator> = Lazy::new(|| {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator
});

pub async fn create_graph_tables(pool: &PgPool) -> std::result::Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

#[derive(Debug, Clone, FromRow)]
struct GraphRow {
    id: Uuid,
    owner_user_id: Uuid,
    owner_group_id: Option<Uuid>,
    kind: String,
    name: String,
    description: Option<String>,
    metadata: serde_json::Value,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone, FromRow)]
struct GraphSummaryRow {
    id: Uuid,
    owner_user_id: Uuid,
    owner_group_id: Option<Uuid>,
    kind: String,
    name: String,
    description: Option<String>,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
    node_count: i64,
    edge_count: i64,
}

#[derive(Debug, Clone, FromRow)]
struct GraphNodeRow {
    id: Uuid,
    label: String,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone, FromRow)]
struct GraphEdgeRow {
    from_node_id: Uuid,
    to_node_id: Uuid,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone, FromRow)]
struct GraphAccessContextRow {
    owner_group_id: Option<Uuid>,
}

fn graph_summary_from_row(value: GraphSummaryRow) -> Result<GraphSummary> {
    let kind = GraphKind::from_db_value(&value.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", value.kind),
        )
    })?;

    Ok(GraphSummary {
        id: GraphId(value.id),
        owner_user_id: UserId(value.owner_user_id),
        owner_group_id: value.owner_group_id.map(GroupId),
        kind,
        name: value.name,
        description: value.description,
        created_at: value.created_at,
        updated_at: value.updated_at,
        node_count: value.node_count,
        edge_count: value.edge_count,
    })
}

fn hydrate_graph(
    row: GraphRow,
    nodes: Vec<GraphNodeRow>,
    edges: Vec<GraphEdgeRow>,
) -> Result<DirectedGraph> {
    let kind = GraphKind::from_db_value(&row.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", row.kind),
        )
    })?;

    let graph_metadata = db_metadata_to_api_json(&row.metadata)
        .map_err(|err| db_metadata_decode_err("Failed to decode graph metadata", err))?;

    let mut output_nodes = Vec::with_capacity(nodes.len());
    for node in nodes {
        let metadata = db_metadata_to_api_json(&node.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph node metadata", err))?;
        output_nodes.push(GraphNode {
            id: GraphNodeId(node.id),
            label: node.label,
            metadata,
        });
    }

    let mut output_edges = Vec::with_capacity(edges.len());
    for edge in edges {
        let metadata = db_metadata_to_api_json(&edge.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph edge metadata", err))?;
        output_edges.push(GraphEdge {
            from_node_id: GraphNodeId(edge.from_node_id),
            to_node_id: GraphNodeId(edge.to_node_id),
            metadata,
        });
    }

    Ok(DirectedGraph {
        id: GraphId(row.id),
        owner_user_id: UserId(row.owner_user_id),
        owner_group_id: row.owner_group_id.map(GroupId),
        kind,
        name: row.name,
        description: row.description,
        metadata: graph_metadata,
        created_at: row.created_at,
        updated_at: row.updated_at,
        nodes: output_nodes,
        edges: output_edges,
    })
}

fn db_err(public: &'static str, err: sqlx::Error) -> LibError {
    LibError::database(public, anyhow!(err))
}

fn db_metadata_decode_err(public: &'static str, err: LibError) -> LibError {
    LibError::database(public, err.source)
}

async fn graph_exists(pool: &PgPool, graph_id: GraphId) -> Result<bool> {
    let exists: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM graph.graphs
            WHERE id = $1
        )
        "#,
    )
    .bind(graph_id.0)
    .fetch_one(pool)
    .await
    .map_err(|err| db_err("Failed to query graph", err))?;

    Ok(exists.0)
}

fn normalize_required_roles(required_roles: &[&str]) -> Result<Vec<String>> {
    let mut dedupe = HashSet::new();
    let roles: Vec<String> = required_roles
        .iter()
        .map(|role| role.trim())
        .filter(|role| !role.is_empty())
        .filter(|role| dedupe.insert((*role).to_string()))
        .map(ToString::to_string)
        .collect();

    if roles.is_empty() {
        return Err(LibError::forbidden(
            "Graph permissions are not configured",
            anyhow!("required graph role set was empty"),
        ));
    }

    Ok(roles)
}

async fn user_has_group_permission_role(
    pool: &PgPool,
    actor: UserId,
    group_id: GroupId,
    required_roles: &[String],
) -> Result<bool> {
    let group_scope_id = permissions::graph_role_scope_id_for_group(group_id);

    let has_role: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM auth.group_memberships gm
            JOIN auth.groups g
              ON g.id = gm.group_id
            JOIN auth.users u
              ON u.id = gm.user_id
            WHERE gm.group_id = $1
              AND gm.user_id = $2
              AND g.active = TRUE
              AND u.active = TRUE
              AND (
                  EXISTS (
                      SELECT 1
                      FROM auth.user_roles ur
                      WHERE ur.user_id = gm.user_id
                        AND ur.scope = $3
                        AND ur.scope_id IN ($4, $5)
                        AND ur.role_name = ANY($6)
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM auth.group_roles gr
                      WHERE gr.group_id = gm.group_id
                        AND gr.scope = $3
                        AND gr.scope_id = gm.group_id::text
                        AND gr.role_name = ANY($6)
                  )
              )
        )
        "#,
    )
    .bind(group_id.0)
    .bind(actor.0)
    .bind(permissions::graph_role_scope())
    .bind(group_scope_id)
    .bind(permissions::graph_role_scope_id_global())
    .bind(required_roles)
    .fetch_one(pool)
    .await
    .map_err(|err| db_err("Failed to query group permissions", err))?;

    Ok(has_role.0)
}

async fn ensure_group_permission(
    pool: &PgPool,
    actor: UserId,
    group_id: GroupId,
    required_roles: &[&str],
    denied_message: &'static str,
) -> Result<()> {
    let normalized_roles = normalize_required_roles(required_roles)?;

    if !group_exists(pool, group_id).await? {
        return Err(LibError::not_found(
            "Group not found",
            anyhow!("group {} not found", group_id),
        ));
    }

    if user_has_group_permission_role(pool, actor, group_id, &normalized_roles).await? {
        Ok(())
    } else {
        Err(LibError::forbidden_missing_scope(
            denied_message,
            permissions::graph_role_scope(),
            permissions::graph_role_scope_id_for_group(group_id),
            normalized_roles,
            anyhow!(
                "user {} lacks required graph roles ({}) for group {}",
                actor,
                required_roles.join(", "),
                group_id
            ),
        ))
    }
}

async fn load_graph_access_context(
    pool: &PgPool,
    graph_id: GraphId,
) -> Result<Option<GraphAccessContextRow>> {
    sqlx::query_as::<_, GraphAccessContextRow>(
        r#"
        SELECT owner_group_id
        FROM graph.graphs
        WHERE id = $1
        LIMIT 1
        "#,
    )
    .bind(graph_id.0)
    .fetch_optional(pool)
    .await
    .map_err(|err| db_err("Failed to query graph", err))
}

fn graph_access_denied_error(
    actor: UserId,
    graph_id: GraphId,
    context: Option<GraphAccessContextRow>,
    required_roles: &[String],
) -> LibError {
    if let Some(context) = context {
        if let Some(group_id) = context.owner_group_id {
            return LibError::forbidden_missing_scope(
                "You do not have access to this graph",
                permissions::graph_role_scope(),
                permissions::graph_role_scope_id_for_group(GroupId(group_id)),
                required_roles.to_vec(),
                anyhow!(
                    "graph {} access denied for user {}; missing required graph roles in group scope {}",
                    graph_id,
                    actor,
                    group_id
                ),
            );
        }
    }

    LibError::forbidden(
        "You do not have access to this graph",
        anyhow!("graph {} access denied for user {}", graph_id, actor),
    )
}

async fn load_accessible_graph(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    group_required_roles: &[&str],
) -> Result<GraphRow> {
    let normalized_roles = normalize_required_roles(group_required_roles)?;

    let row = sqlx::query_as::<_, GraphRow>(
        r#"
        SELECT
            g.id,
            g.owner_user_id,
            g.owner_group_id,
            g.kind,
            g.name,
            g.description,
            g.metadata,
            g.created_at,
            g.updated_at
        FROM graph.graphs g
        WHERE g.id = $1
          AND (
              (g.owner_group_id IS NULL AND g.owner_user_id = $2)
              OR (
                  g.owner_group_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM auth.group_memberships gm
                      JOIN auth.groups grp
                        ON grp.id = gm.group_id
                      JOIN auth.users usr
                        ON usr.id = gm.user_id
                    WHERE gm.group_id = g.owner_group_id
                      AND gm.user_id = $2
                      AND grp.active = TRUE
                      AND usr.active = TRUE
                      AND (
                            EXISTS (
                                SELECT 1
                                FROM auth.user_roles ur
                                WHERE ur.user_id = gm.user_id
                                  AND ur.scope = $3
                                  AND ur.scope_id IN (gm.group_id::text, $4)
                                  AND ur.role_name = ANY($5)
                            )
                            OR EXISTS (
                                SELECT 1
                                FROM auth.group_roles gr
                                WHERE gr.group_id = gm.group_id
                                  AND gr.scope = $3
                                  AND gr.scope_id = gm.group_id::text
                                  AND gr.role_name = ANY($5)
                            )
                        )
                  )
              )
          )
        LIMIT 1
        "#,
    )
    .bind(graph_id.0)
    .bind(actor.0)
    .bind(permissions::graph_role_scope())
    .bind(permissions::graph_role_scope_id_global())
    .bind(&normalized_roles)
    .fetch_optional(pool)
    .await
    .map_err(|err| db_err("Failed to query graph", err))?;

    if let Some(row) = row {
        Ok(row)
    } else if graph_exists(pool, graph_id).await? {
        let context = load_graph_access_context(pool, graph_id).await?;
        Err(graph_access_denied_error(
            actor,
            graph_id,
            context,
            &normalized_roles,
        ))
    } else {
        Err(LibError::not_found(
            "Graph not found",
            anyhow!("graph {} not found", graph_id),
        ))
    }
}

async fn load_accessible_graph_for_update_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    group_required_roles: &[&str],
    expected_updated_at: Option<NaiveDateTime>,
) -> Result<GraphRow> {
    let normalized_roles = normalize_required_roles(group_required_roles)?;

    let row = sqlx::query_as::<_, GraphRow>(
        r#"
        SELECT
            g.id,
            g.owner_user_id,
            g.owner_group_id,
            g.kind,
            g.name,
            g.description,
            g.metadata,
            g.created_at,
            g.updated_at
        FROM graph.graphs g
        WHERE g.id = $1
          AND (
              (g.owner_group_id IS NULL AND g.owner_user_id = $2)
              OR (
                  g.owner_group_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM auth.group_memberships gm
                      JOIN auth.groups grp
                        ON grp.id = gm.group_id
                      JOIN auth.users usr
                        ON usr.id = gm.user_id
                    WHERE gm.group_id = g.owner_group_id
                      AND gm.user_id = $2
                      AND grp.active = TRUE
                      AND usr.active = TRUE
                      AND (
                            EXISTS (
                                SELECT 1
                                FROM auth.user_roles ur
                                WHERE ur.user_id = gm.user_id
                                  AND ur.scope = $3
                                  AND ur.scope_id IN (gm.group_id::text, $4)
                                  AND ur.role_name = ANY($5)
                            )
                            OR EXISTS (
                                SELECT 1
                                FROM auth.group_roles gr
                                WHERE gr.group_id = gm.group_id
                                  AND gr.scope = $3
                                  AND gr.scope_id = gm.group_id::text
                                  AND gr.role_name = ANY($5)
                            )
                        )
                  )
              )
          )
        LIMIT 1
        FOR UPDATE
        "#,
    )
    .bind(graph_id.0)
    .bind(actor.0)
    .bind(permissions::graph_role_scope())
    .bind(permissions::graph_role_scope_id_global())
    .bind(&normalized_roles)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to query graph", err))?;

    let Some(row) = row else {
        return if graph_exists(pool, graph_id).await? {
            let context = load_graph_access_context(pool, graph_id).await?;
            Err(graph_access_denied_error(
                actor,
                graph_id,
                context,
                &normalized_roles,
            ))
        } else {
            Err(LibError::not_found(
                "Graph not found",
                anyhow!("graph {} not found", graph_id),
            ))
        };
    };

    if let Some(expected_updated_at) = expected_updated_at {
        if row.updated_at != expected_updated_at {
            return Err(LibError::conflict(
                "stale_graph_update",
                "Graph has changed since it was last read",
                anyhow!(
                    "optimistic concurrency check failed for graph {}; expected updated_at {}, actual {}",
                    graph_id,
                    expected_updated_at,
                    row.updated_at
                ),
            ));
        }
    }

    Ok(row)
}

async fn load_graph_nodes_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    graph_id: GraphId,
) -> Result<Vec<GraphNode>> {
    let rows = sqlx::query_as::<_, GraphNodeRow>(
        r#"
        SELECT id, label, metadata
        FROM graph.nodes
        WHERE graph_id = $1
        ORDER BY id ASC
        "#,
    )
    .bind(graph_id.0)
    .fetch_all(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to query graph nodes", err))?;

    let mut nodes = Vec::with_capacity(rows.len());
    for node in rows {
        let metadata = db_metadata_to_api_json(&node.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph node metadata", err))?;
        nodes.push(GraphNode {
            id: GraphNodeId(node.id),
            label: node.label,
            metadata,
        });
    }

    Ok(nodes)
}

async fn load_graph_edges_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    graph_id: GraphId,
) -> Result<Vec<GraphEdge>> {
    let rows = sqlx::query_as::<_, GraphEdgeRow>(
        r#"
        SELECT from_node_id, to_node_id, metadata
        FROM graph.edges
        WHERE graph_id = $1
        ORDER BY from_node_id ASC, to_node_id ASC
        "#,
    )
    .bind(graph_id.0)
    .fetch_all(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to query graph edges", err))?;

    let mut edges = Vec::with_capacity(rows.len());
    for edge in rows {
        let metadata = db_metadata_to_api_json(&edge.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph edge metadata", err))?;
        edges.push(GraphEdge {
            from_node_id: GraphNodeId(edge.from_node_id),
            to_node_id: GraphNodeId(edge.to_node_id),
            metadata,
        });
    }

    Ok(edges)
}

fn update_graph_definition_node(
    nodes: &mut Vec<GraphNode>,
    payload: &UpsertNodePayload,
) -> Result<(GraphNodeId, bool)> {
    let label = payload.label.trim().to_string();
    if label.is_empty() {
        return Err(LibError::invalid(
            "Node label is required",
            anyhow!("empty node label"),
        ));
    }

    if let Some(node_id) = payload.node_id {
        if let Some(node) = nodes.iter_mut().find(|node| node.id == node_id) {
            node.label = label;
            if let Some(metadata) = &payload.metadata {
                node.metadata = normalize_api_metadata(Some(metadata.clone()))?;
            }
            Ok((node_id, false))
        } else {
            nodes.push(GraphNode {
                id: node_id,
                label,
                metadata: normalize_api_metadata(payload.metadata.clone())?,
            });
            Ok((node_id, true))
        }
    } else {
        let new_id = GraphNodeId(Uuid::new_v4());
        nodes.push(GraphNode {
            id: new_id,
            label,
            metadata: normalize_api_metadata(payload.metadata.clone())?,
        });
        Ok((new_id, true))
    }
}

fn apply_reparent_edges(
    edges: &[GraphEdge],
    node_id: GraphNodeId,
    new_parent_node_id: Option<GraphNodeId>,
    metadata_override: Option<Value>,
) -> Vec<GraphEdge> {
    let existing_metadata = new_parent_node_id.and_then(|parent_id| {
        edges
            .iter()
            .find(|edge| edge.from_node_id == parent_id && edge.to_node_id == node_id)
            .map(|edge| edge.metadata.clone())
    });

    let mut updated_edges = edges
        .iter()
        .filter(|edge| edge.to_node_id != node_id)
        .cloned()
        .collect::<Vec<_>>();

    if let Some(parent_id) = new_parent_node_id {
        updated_edges.push(GraphEdge {
            from_node_id: parent_id,
            to_node_id: node_id,
            metadata: metadata_override
                .or(existing_metadata)
                .unwrap_or_else(|| Value::Object(Default::default())),
        });
    }

    updated_edges
}

async fn touch_graph_updated_at_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    graph_id: GraphId,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE graph.graphs
        SET updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        "#,
    )
    .bind(graph_id.0)
    .execute(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to update graph timestamp", err))?;
    Ok(())
}

async fn write_graph_contents(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    graph_id: GraphId,
    definition: &GraphDefinition,
) -> Result<()> {
    crate::invariants::ensure_graph_invariants(
        definition.kind,
        &definition.nodes,
        &definition.edges,
    )?;

    for node in &definition.nodes {
        let metadata = api_metadata_to_db_json(&node.metadata)?;
        sqlx::query(
            r#"
            INSERT INTO graph.nodes (id, graph_id, label, metadata)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(node.id.0)
        .bind(graph_id.0)
        .bind(&node.label)
        .bind(metadata)
        .execute(&mut **tx)
        .await
        .map_err(|err| db_err("Failed to write graph nodes", err))?;
    }

    for edge in &definition.edges {
        let metadata = api_metadata_to_db_json(&edge.metadata)?;
        sqlx::query(
            r#"
            INSERT INTO graph.edges (graph_id, from_node_id, to_node_id, metadata)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(graph_id.0)
        .bind(edge.from_node_id.0)
        .bind(edge.to_node_id.0)
        .bind(metadata)
        .execute(&mut **tx)
        .await
        .map_err(|err| db_err("Failed to write graph edges", err))?;
    }

    Ok(())
}

pub async fn create_graph(
    pool: &PgPool,
    actor: UserId,
    payload: CreateGraphPayload,
    group_create_roles: &[&str],
) -> Result<DirectedGraph> {
    let definition = payload.normalize()?;
    crate::invariants::ensure_graph_invariants(
        definition.kind,
        &definition.nodes,
        &definition.edges,
    )?;
    let graph_metadata = api_metadata_to_db_json(&definition.metadata)?;
    if let Some(group_id) = definition.owner_group_id {
        ensure_group_permission(
            pool,
            actor,
            group_id,
            group_create_roles,
            "You do not have permission to create graphs for this group",
        )
        .await?;
    }

    let graph_id = GraphId(Uuid::new_v4());
    let owner_group_id = definition.owner_group_id.map(|id| id.0);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;

    sqlx::query(
        r#"
        INSERT INTO graph.graphs (
            id,
            owner_user_id,
            owner_group_id,
            kind,
            name,
            description,
            metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(graph_id.0)
    .bind(actor.0)
    .bind(owner_group_id)
    .bind(definition.kind.as_db_value())
    .bind(&definition.name)
    .bind(&definition.description)
    .bind(graph_metadata)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to create graph", err))?;

    write_graph_contents(&mut tx, graph_id, &definition).await?;

    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;

    get_graph(pool, actor, graph_id, group_create_roles).await
}

pub async fn get_graph(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    group_read_roles: &[&str],
) -> Result<DirectedGraph> {
    let graph = load_accessible_graph(pool, actor, graph_id, group_read_roles).await?;
    let nodes = sqlx::query_as::<_, GraphNodeRow>(
        r#"
        SELECT id, label, metadata
        FROM graph.nodes
        WHERE graph_id = $1
        ORDER BY label ASC, id ASC
        "#,
    )
    .bind(graph_id.0)
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to query graph nodes", err))?;

    let edges = sqlx::query_as::<_, GraphEdgeRow>(
        r#"
        SELECT from_node_id, to_node_id, metadata
        FROM graph.edges
        WHERE graph_id = $1
        ORDER BY from_node_id ASC, to_node_id ASC
        "#,
    )
    .bind(graph_id.0)
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to query graph edges", err))?;

    hydrate_graph(graph, nodes, edges)
}

pub async fn list_graphs(
    pool: &PgPool,
    actor: UserId,
    page: u32,
    limit: u32,
    group_read_roles: &[&str],
) -> Result<Vec<GraphSummary>> {
    let offset = (page.saturating_sub(1) as i64).saturating_mul(limit as i64);
    let normalized_roles = normalize_required_roles(group_read_roles)?;

    let rows = sqlx::query_as::<_, GraphSummaryRow>(
        r#"
        SELECT
            g.id,
            g.owner_user_id,
            g.owner_group_id,
            g.kind,
            g.name,
            g.description,
            g.created_at,
            g.updated_at,
            COALESCE(n.node_count, 0) AS node_count,
            COALESCE(e.edge_count, 0) AS edge_count
        FROM graph.graphs g
        LEFT JOIN (
            SELECT graph_id, COUNT(*)::bigint AS node_count
            FROM graph.nodes
            GROUP BY graph_id
        ) n
        ON n.graph_id = g.id
        LEFT JOIN (
            SELECT graph_id, COUNT(*)::bigint AS edge_count
            FROM graph.edges
            GROUP BY graph_id
        ) e
        ON e.graph_id = g.id
        WHERE (
            (g.owner_group_id IS NULL AND g.owner_user_id = $1)
            OR (
                g.owner_group_id IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM auth.group_memberships gm
                    JOIN auth.groups grp
                      ON grp.id = gm.group_id
                    JOIN auth.users usr
                      ON usr.id = gm.user_id
                    WHERE gm.group_id = g.owner_group_id
                      AND gm.user_id = $1
                      AND grp.active = TRUE
                      AND usr.active = TRUE
                      AND (
                          EXISTS (
                              SELECT 1
                              FROM auth.user_roles ur
                              WHERE ur.user_id = gm.user_id
                                AND ur.scope = $5
                                AND ur.scope_id IN (gm.group_id::text, $6)
                                AND ur.role_name = ANY($4)
                          )
                          OR EXISTS (
                              SELECT 1
                              FROM auth.group_roles gr
                              WHERE gr.group_id = gm.group_id
                                AND gr.scope = $5
                                AND gr.scope_id = gm.group_id::text
                                AND gr.role_name = ANY($4)
                          )
                      )
                )
            )
        )
        ORDER BY g.updated_at DESC, g.id DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(actor.0)
    .bind(limit as i64)
    .bind(offset)
    .bind(normalized_roles)
    .bind(permissions::graph_role_scope())
    .bind(permissions::graph_role_scope_id_global())
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to list graphs", err))?;

    rows.into_iter().map(graph_summary_from_row).collect()
}

pub async fn update_graph(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpdateGraphPayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let definition = payload.normalize()?;
    crate::invariants::ensure_graph_invariants(
        definition.kind,
        &definition.nodes,
        &definition.edges,
    )?;
    let graph_metadata = api_metadata_to_db_json(&definition.metadata)?;

    if let Some(group_id) = definition.owner_group_id {
        ensure_group_permission(
            pool,
            actor,
            group_id,
            group_update_roles,
            "You do not have permission to update graphs for this group",
        )
        .await?;
    }
    let normalized_roles = normalize_required_roles(group_update_roles)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;

    let updated = sqlx::query(
        r#"
        UPDATE graph.graphs
        SET owner_group_id = $1,
            kind = $2,
            name = $3,
            description = $4,
            metadata = $5,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $6
          AND (
              (owner_group_id IS NULL AND owner_user_id = $7)
              OR (
                  owner_group_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM auth.group_memberships gm
                      JOIN auth.groups grp
                        ON grp.id = gm.group_id
                      JOIN auth.users usr
                        ON usr.id = gm.user_id
                      WHERE gm.group_id = graph.graphs.owner_group_id
                        AND gm.user_id = $7
                        AND grp.active = TRUE
                        AND usr.active = TRUE
                        AND (
                            EXISTS (
                                SELECT 1
                                FROM auth.user_roles ur
                                WHERE ur.user_id = gm.user_id
                                  AND ur.scope = $9
                                  AND ur.scope_id IN (gm.group_id::text, $10)
                                  AND ur.role_name = ANY($8)
                            )
                            OR EXISTS (
                                SELECT 1
                                FROM auth.group_roles gr
                                WHERE gr.group_id = gm.group_id
                                  AND gr.scope = $9
                                  AND gr.scope_id = gm.group_id::text
                                  AND gr.role_name = ANY($8)
                            )
                        )
                  )
              )
          )
        "#,
    )
    .bind(definition.owner_group_id.map(|id| id.0))
    .bind(definition.kind.as_db_value())
    .bind(&definition.name)
    .bind(&definition.description)
    .bind(graph_metadata)
    .bind(graph_id.0)
    .bind(actor.0)
    .bind(&normalized_roles)
    .bind(permissions::graph_role_scope())
    .bind(permissions::graph_role_scope_id_global())
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to update graph", err))?;

    if updated.rows_affected() == 0 {
        tx.rollback()
            .await
            .map_err(|err| db_err("Failed to rollback transaction", err))?;

        return if graph_exists(pool, graph_id).await? {
            let context = load_graph_access_context(pool, graph_id).await?;
            Err(graph_access_denied_error(
                actor,
                graph_id,
                context,
                &normalized_roles,
            ))
        } else {
            Err(LibError::not_found(
                "Graph not found",
                anyhow!("graph {} not found", graph_id),
            ))
        };
    }

    sqlx::query(
        r#"
        DELETE FROM graph.edges
        WHERE graph_id = $1
        "#,
    )
    .bind(graph_id.0)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to replace graph edges", err))?;

    sqlx::query(
        r#"
        DELETE FROM graph.nodes
        WHERE graph_id = $1
        "#,
    )
    .bind(graph_id.0)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to replace graph nodes", err))?;

    write_graph_contents(&mut tx, graph_id, &definition).await?;

    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;

    get_graph(pool, actor, graph_id, group_update_roles).await
}

fn invariant_violation_error(
    kind: GraphKind,
    violations: Vec<crate::models::GraphInvariantViolation>,
) -> LibError {
    let first = violations
        .first()
        .expect("invariant_violation_error requires at least one violation");
    LibError::invalid_with_code(
        first.error_code(kind),
        first.public_message(kind),
        anyhow!(
            "graph invariant violation for kind {}: {:?}",
            kind.as_db_value(),
            violations
        ),
    )
}

pub async fn update_graph_with_guard(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpdateGraphPayload,
    expected_updated_at: Option<NaiveDateTime>,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let definition = payload.normalize()?;
    crate::invariants::ensure_graph_invariants(
        definition.kind,
        &definition.nodes,
        &definition.edges,
    )?;
    let graph_metadata = api_metadata_to_db_json(&definition.metadata)?;

    if let Some(group_id) = definition.owner_group_id {
        ensure_group_permission(
            pool,
            actor,
            group_id,
            group_update_roles,
            "You do not have permission to update graphs for this group",
        )
        .await?;
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;

    let _locked = load_accessible_graph_for_update_tx(
        &mut tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        expected_updated_at,
    )
    .await?;

    sqlx::query(
        r#"
        UPDATE graph.graphs
        SET owner_group_id = $1,
            kind = $2,
            name = $3,
            description = $4,
            metadata = $5,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $6
        "#,
    )
    .bind(definition.owner_group_id.map(|id| id.0))
    .bind(definition.kind.as_db_value())
    .bind(&definition.name)
    .bind(&definition.description)
    .bind(graph_metadata)
    .bind(graph_id.0)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to update graph", err))?;

    sqlx::query(
        r#"
        DELETE FROM graph.edges
        WHERE graph_id = $1
        "#,
    )
    .bind(graph_id.0)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to replace graph edges", err))?;

    sqlx::query(
        r#"
        DELETE FROM graph.nodes
        WHERE graph_id = $1
        "#,
    )
    .bind(graph_id.0)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to replace graph nodes", err))?;

    write_graph_contents(&mut tx, graph_id, &definition).await?;

    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;

    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn add_edge_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: AddEdgePayload,
    group_update_roles: &[&str],
) -> Result<()> {
    let AddEdgePayload {
        from_node_id,
        to_node_id,
        metadata,
        expected_updated_at,
    } = payload;
    let graph = load_accessible_graph_for_update_tx(
        tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        expected_updated_at,
    )
    .await?;
    let kind = GraphKind::from_db_value(&graph.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", graph.kind),
        )
    })?;

    let nodes = load_graph_nodes_tx(tx, graph_id).await?;
    let edges = load_graph_edges_tx(tx, graph_id).await?;
    let index = crate::invariants::GraphMutationIndex::new(kind, &nodes, &edges);
    let violations = index.would_add_edge_violations(from_node_id, to_node_id);
    if !violations.is_empty() {
        return Err(invariant_violation_error(kind, violations));
    }
    let edge_metadata = api_metadata_to_db_json(&normalize_api_metadata(metadata)?)?;

    let inserted = sqlx::query(
        r#"
        INSERT INTO graph.edges (graph_id, from_node_id, to_node_id, metadata)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(graph_id.0)
    .bind(from_node_id.0)
    .bind(to_node_id.0)
    .bind(edge_metadata)
    .execute(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to add graph edge", err))?;

    if inserted.rows_affected() == 0 {
        return Err(LibError::invalid(
            "Edge already exists in graph",
            anyhow!(
                "edge {} -> {} already exists in graph {}",
                from_node_id,
                to_node_id,
                graph_id
            ),
        ));
    }

    touch_graph_updated_at_tx(tx, graph_id).await
}

pub async fn remove_edge_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: RemoveEdgePayload,
    group_update_roles: &[&str],
) -> Result<()> {
    let graph = load_accessible_graph_for_update_tx(
        tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        payload.expected_updated_at,
    )
    .await?;
    let kind = GraphKind::from_db_value(&graph.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", graph.kind),
        )
    })?;

    let nodes = load_graph_nodes_tx(tx, graph_id).await?;
    let edges = load_graph_edges_tx(tx, graph_id).await?;
    if !edges.iter().any(|edge| {
        edge.from_node_id == payload.from_node_id && edge.to_node_id == payload.to_node_id
    }) {
        return Err(LibError::not_found(
            "Edge not found",
            anyhow!(
                "edge {} -> {} not found in graph {}",
                payload.from_node_id,
                payload.to_node_id,
                graph_id
            ),
        ));
    }

    let index = crate::invariants::GraphMutationIndex::new(kind, &nodes, &edges);
    let violations = index.would_remove_edge_violations(payload.from_node_id, payload.to_node_id);
    if !violations.is_empty() {
        return Err(invariant_violation_error(kind, violations));
    }

    sqlx::query(
        r#"
        DELETE FROM graph.edges
        WHERE graph_id = $1
          AND from_node_id = $2
          AND to_node_id = $3
        "#,
    )
    .bind(graph_id.0)
    .bind(payload.from_node_id.0)
    .bind(payload.to_node_id.0)
    .execute(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to remove graph edge", err))?;

    touch_graph_updated_at_tx(tx, graph_id).await
}

pub async fn upsert_edge_metadata_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpsertEdgeMetadataPayload,
    group_update_roles: &[&str],
) -> Result<()> {
    let UpsertEdgeMetadataPayload {
        from_node_id,
        to_node_id,
        metadata,
        expected_updated_at,
    } = payload;
    let graph = load_accessible_graph_for_update_tx(
        tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        expected_updated_at,
    )
    .await?;
    let kind = GraphKind::from_db_value(&graph.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", graph.kind),
        )
    })?;

    let nodes = load_graph_nodes_tx(tx, graph_id).await?;
    let edges = load_graph_edges_tx(tx, graph_id).await?;
    let edge_exists = edges
        .iter()
        .any(|edge| edge.from_node_id == from_node_id && edge.to_node_id == to_node_id);
    if !edge_exists {
        let index = crate::invariants::GraphMutationIndex::new(kind, &nodes, &edges);
        let violations = index.would_add_edge_violations(from_node_id, to_node_id);
        if !violations.is_empty() {
            return Err(invariant_violation_error(kind, violations));
        }
    }
    let edge_metadata = api_metadata_to_db_json(&normalize_api_metadata(Some(metadata))?)?;

    sqlx::query(
        r#"
        INSERT INTO graph.edges (graph_id, from_node_id, to_node_id, metadata)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (graph_id, from_node_id, to_node_id)
        DO UPDATE SET metadata = EXCLUDED.metadata
        "#,
    )
    .bind(graph_id.0)
    .bind(from_node_id.0)
    .bind(to_node_id.0)
    .bind(edge_metadata)
    .execute(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to upsert graph edge metadata", err))?;

    touch_graph_updated_at_tx(tx, graph_id).await
}

pub async fn upsert_node_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpsertNodePayload,
    group_update_roles: &[&str],
) -> Result<GraphNodeId> {
    let graph = load_accessible_graph_for_update_tx(
        tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        payload.expected_updated_at,
    )
    .await?;
    let kind = GraphKind::from_db_value(&graph.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", graph.kind),
        )
    })?;

    let mut nodes = load_graph_nodes_tx(tx, graph_id).await?;
    let edges = load_graph_edges_tx(tx, graph_id).await?;
    let (node_id, inserted) = update_graph_definition_node(&mut nodes, &payload)?;
    let violations = crate::invariants::graph_invariant_violations(kind, &nodes, &edges);
    if !violations.is_empty() {
        return Err(invariant_violation_error(kind, violations));
    }

    let (label, metadata) = nodes
        .iter()
        .find(|node| node.id == node_id)
        .map(|node| (node.label.clone(), node.metadata.clone()))
        .expect("updated node should exist");
    let db_metadata = api_metadata_to_db_json(&metadata)?;

    if inserted {
        sqlx::query(
            r#"
            INSERT INTO graph.nodes (id, graph_id, label, metadata)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(node_id.0)
        .bind(graph_id.0)
        .bind(label)
        .bind(&db_metadata)
        .execute(&mut **tx)
        .await
        .map_err(|err| db_err("Failed to insert graph node", err))?;
    } else {
        sqlx::query(
            r#"
            UPDATE graph.nodes
            SET label = $1,
                metadata = $2
            WHERE graph_id = $3
              AND id = $4
            "#,
        )
        .bind(label)
        .bind(&db_metadata)
        .bind(graph_id.0)
        .bind(node_id.0)
        .execute(&mut **tx)
        .await
        .map_err(|err| db_err("Failed to update graph node", err))?;
    }

    touch_graph_updated_at_tx(tx, graph_id).await?;
    Ok(node_id)
}

pub async fn remove_node_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: RemoveNodePayload,
    group_update_roles: &[&str],
) -> Result<()> {
    let graph = load_accessible_graph_for_update_tx(
        tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        payload.expected_updated_at,
    )
    .await?;
    let kind = GraphKind::from_db_value(&graph.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", graph.kind),
        )
    })?;

    let mut nodes = load_graph_nodes_tx(tx, graph_id).await?;
    let mut edges = load_graph_edges_tx(tx, graph_id).await?;
    if !nodes.iter().any(|node| node.id == payload.node_id) {
        return Err(LibError::not_found(
            "Node not found",
            anyhow!("node {} not found in graph {}", payload.node_id, graph_id),
        ));
    }

    nodes.retain(|node| node.id != payload.node_id);
    if nodes.is_empty() {
        return Err(LibError::invalid(
            "Graph must contain at least one node",
            anyhow!(
                "removing node {} would empty graph {}",
                payload.node_id,
                graph_id
            ),
        ));
    }
    edges.retain(|edge| edge.from_node_id != payload.node_id && edge.to_node_id != payload.node_id);
    let violations = crate::invariants::graph_invariant_violations(kind, &nodes, &edges);
    if !violations.is_empty() {
        return Err(invariant_violation_error(kind, violations));
    }

    sqlx::query(
        r#"
        DELETE FROM graph.nodes
        WHERE graph_id = $1
          AND id = $2
        "#,
    )
    .bind(graph_id.0)
    .bind(payload.node_id.0)
    .execute(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to remove graph node", err))?;

    touch_graph_updated_at_tx(tx, graph_id).await
}

pub async fn reparent_node_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: ReparentNodePayload,
    group_update_roles: &[&str],
) -> Result<()> {
    let ReparentNodePayload {
        node_id,
        new_parent_node_id,
        metadata,
        expected_updated_at,
    } = payload;
    if new_parent_node_id.is_none() && metadata.is_some() {
        return Err(LibError::invalid(
            "Metadata can only be provided when assigning a parent edge",
            anyhow!("metadata provided for detach request on node {}", node_id),
        ));
    }

    let graph = load_accessible_graph_for_update_tx(
        tx,
        pool,
        actor,
        graph_id,
        group_update_roles,
        expected_updated_at,
    )
    .await?;
    let kind = GraphKind::from_db_value(&graph.kind).ok_or_else(|| {
        LibError::database(
            "Failed to decode graph kind",
            anyhow!("unknown graph kind value '{}'", graph.kind),
        )
    })?;

    let nodes = load_graph_nodes_tx(tx, graph_id).await?;
    let node_ids: HashSet<GraphNodeId> = nodes.iter().map(|node| node.id).collect();
    if !node_ids.contains(&node_id) {
        return Err(LibError::not_found(
            "Node not found",
            anyhow!("node {} not found in graph {}", node_id, graph_id),
        ));
    }
    if let Some(parent_node_id) = new_parent_node_id {
        if !node_ids.contains(&parent_node_id) {
            return Err(LibError::not_found(
                "Parent node not found",
                anyhow!(
                    "parent node {} not found in graph {}",
                    parent_node_id,
                    graph_id
                ),
            ));
        }
    }

    let edges = load_graph_edges_tx(tx, graph_id).await?;
    let metadata_override = metadata
        .map(|value| normalize_api_metadata(Some(value)))
        .transpose()?;
    let updated_edges =
        apply_reparent_edges(&edges, node_id, new_parent_node_id, metadata_override);
    let violations = crate::invariants::graph_invariant_violations(kind, &nodes, &updated_edges);
    if !violations.is_empty() {
        return Err(invariant_violation_error(kind, violations));
    }

    sqlx::query(
        r#"
        DELETE FROM graph.edges
        WHERE graph_id = $1
          AND to_node_id = $2
        "#,
    )
    .bind(graph_id.0)
    .bind(node_id.0)
    .execute(&mut **tx)
    .await
    .map_err(|err| db_err("Failed to remove existing parent edge", err))?;

    if let Some(parent_node_id) = new_parent_node_id {
        let metadata = updated_edges
            .iter()
            .find(|edge| edge.from_node_id == parent_node_id && edge.to_node_id == node_id)
            .map(|edge| edge.metadata.clone())
            .expect("reparented edge should exist after edge update");
        let db_metadata = api_metadata_to_db_json(&metadata)?;

        sqlx::query(
            r#"
            INSERT INTO graph.edges (graph_id, from_node_id, to_node_id, metadata)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (graph_id, from_node_id, to_node_id)
            DO UPDATE SET metadata = EXCLUDED.metadata
            "#,
        )
        .bind(graph_id.0)
        .bind(parent_node_id.0)
        .bind(node_id.0)
        .bind(db_metadata)
        .execute(&mut **tx)
        .await
        .map_err(|err| db_err("Failed to save reparented edge", err))?;
    }

    touch_graph_updated_at_tx(tx, graph_id).await
}

pub async fn add_edge(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: AddEdgePayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;
    add_edge_tx(&mut tx, pool, actor, graph_id, payload, group_update_roles).await?;
    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;
    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn remove_edge(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: RemoveEdgePayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;
    remove_edge_tx(&mut tx, pool, actor, graph_id, payload, group_update_roles).await?;
    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;
    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn upsert_edge_metadata(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpsertEdgeMetadataPayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;
    upsert_edge_metadata_tx(&mut tx, pool, actor, graph_id, payload, group_update_roles).await?;
    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;
    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn upsert_node(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpsertNodePayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;
    upsert_node_tx(&mut tx, pool, actor, graph_id, payload, group_update_roles).await?;
    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;
    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn remove_node(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: RemoveNodePayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;
    remove_node_tx(&mut tx, pool, actor, graph_id, payload, group_update_roles).await?;
    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;
    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn reparent_node(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: ReparentNodePayload,
    group_update_roles: &[&str],
) -> Result<DirectedGraph> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;
    reparent_node_tx(&mut tx, pool, actor, graph_id, payload, group_update_roles).await?;
    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;
    get_graph(pool, actor, graph_id, group_update_roles).await
}

pub async fn apply_graph_delta_batch_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    actor: UserId,
    commands: &[GraphDeltaCommand],
    group_update_roles: &[&str],
) -> Result<()> {
    for command in commands {
        match &command.operation {
            GraphDeltaOperation::AddEdge {
                from_node_id,
                to_node_id,
                metadata,
            } => {
                add_edge_tx(
                    tx,
                    pool,
                    actor,
                    command.graph_id,
                    AddEdgePayload {
                        from_node_id: *from_node_id,
                        to_node_id: *to_node_id,
                        metadata: metadata.clone(),
                        expected_updated_at: command.expected_updated_at,
                    },
                    group_update_roles,
                )
                .await?;
            }
            GraphDeltaOperation::RemoveEdge {
                from_node_id,
                to_node_id,
            } => {
                remove_edge_tx(
                    tx,
                    pool,
                    actor,
                    command.graph_id,
                    RemoveEdgePayload {
                        from_node_id: *from_node_id,
                        to_node_id: *to_node_id,
                        expected_updated_at: command.expected_updated_at,
                    },
                    group_update_roles,
                )
                .await?;
            }
            GraphDeltaOperation::UpsertEdgeMetadata {
                from_node_id,
                to_node_id,
                metadata,
            } => {
                upsert_edge_metadata_tx(
                    tx,
                    pool,
                    actor,
                    command.graph_id,
                    UpsertEdgeMetadataPayload {
                        from_node_id: *from_node_id,
                        to_node_id: *to_node_id,
                        metadata: metadata.clone(),
                        expected_updated_at: command.expected_updated_at,
                    },
                    group_update_roles,
                )
                .await?;
            }
            GraphDeltaOperation::UpsertNode {
                node_id,
                label,
                metadata,
            } => {
                upsert_node_tx(
                    tx,
                    pool,
                    actor,
                    command.graph_id,
                    UpsertNodePayload {
                        node_id: *node_id,
                        label: label.clone(),
                        metadata: metadata.clone(),
                        expected_updated_at: command.expected_updated_at,
                    },
                    group_update_roles,
                )
                .await?;
            }
            GraphDeltaOperation::ReparentNode {
                node_id,
                new_parent_node_id,
                metadata,
            } => {
                reparent_node_tx(
                    tx,
                    pool,
                    actor,
                    command.graph_id,
                    ReparentNodePayload {
                        node_id: *node_id,
                        new_parent_node_id: *new_parent_node_id,
                        metadata: metadata.clone(),
                        expected_updated_at: command.expected_updated_at,
                    },
                    group_update_roles,
                )
                .await?;
            }
            GraphDeltaOperation::RemoveNode { node_id } => {
                remove_node_tx(
                    tx,
                    pool,
                    actor,
                    command.graph_id,
                    RemoveNodePayload {
                        node_id: *node_id,
                        expected_updated_at: command.expected_updated_at,
                    },
                    group_update_roles,
                )
                .await?;
            }
        }
    }

    Ok(())
}

pub async fn find_node_by_external_id(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    external_id: &str,
    group_read_roles: &[&str],
) -> Result<Option<GraphNode>> {
    let _ = load_accessible_graph(pool, actor, graph_id, group_read_roles).await?;
    let node = sqlx::query_as::<_, GraphNodeRow>(
        r#"
        SELECT id, label, metadata
        FROM graph.nodes
        WHERE graph_id = $1
          AND metadata ->> 'external_id' = $2
        LIMIT 1
        "#,
    )
    .bind(graph_id.0)
    .bind(external_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| db_err("Failed to query node by external id", err))?;

    let Some(node) = node else {
        return Ok(None);
    };

    let metadata = db_metadata_to_api_json(&node.metadata)
        .map_err(|err| db_metadata_decode_err("Failed to decode graph node metadata", err))?;

    Ok(Some(GraphNode {
        id: GraphNodeId(node.id),
        label: node.label,
        metadata,
    }))
}

pub async fn list_incident_edges_for_node(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    node_id: GraphNodeId,
    group_read_roles: &[&str],
) -> Result<Vec<GraphEdge>> {
    let _ = load_accessible_graph(pool, actor, graph_id, group_read_roles).await?;
    let edges = sqlx::query_as::<_, GraphEdgeRow>(
        r#"
        SELECT from_node_id, to_node_id, metadata
        FROM graph.edges
        WHERE graph_id = $1
          AND (from_node_id = $2 OR to_node_id = $2)
        ORDER BY from_node_id ASC, to_node_id ASC
        "#,
    )
    .bind(graph_id.0)
    .bind(node_id.0)
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to query incident edges", err))?;

    let mut output = Vec::with_capacity(edges.len());
    for edge in edges {
        let metadata = db_metadata_to_api_json(&edge.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph edge metadata", err))?;
        output.push(GraphEdge {
            from_node_id: GraphNodeId(edge.from_node_id),
            to_node_id: GraphNodeId(edge.to_node_id),
            metadata,
        });
    }

    Ok(output)
}

pub async fn list_incident_edges_for_external_id(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    external_id: &str,
    group_read_roles: &[&str],
) -> Result<Vec<GraphEdge>> {
    let Some(node) =
        find_node_by_external_id(pool, actor, graph_id, external_id, group_read_roles).await?
    else {
        return Ok(Vec::new());
    };

    list_incident_edges_for_node(pool, actor, graph_id, node.id, group_read_roles).await
}

pub async fn list_graph_nodes_by_metadata(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    metadata_contains: &Value,
    group_read_roles: &[&str],
) -> Result<Vec<GraphNode>> {
    let _ = load_accessible_graph(pool, actor, graph_id, group_read_roles).await?;
    let metadata_filter = api_metadata_to_db_json(metadata_contains)?;
    let rows = sqlx::query_as::<_, GraphNodeRow>(
        r#"
        SELECT id, label, metadata
        FROM graph.nodes
        WHERE graph_id = $1
          AND metadata @> $2::jsonb
        ORDER BY id ASC
        "#,
    )
    .bind(graph_id.0)
    .bind(metadata_filter)
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to query graph nodes by metadata", err))?;

    let mut nodes = Vec::with_capacity(rows.len());
    for row in rows {
        let metadata = db_metadata_to_api_json(&row.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph node metadata", err))?;
        nodes.push(GraphNode {
            id: GraphNodeId(row.id),
            label: row.label,
            metadata,
        });
    }

    Ok(nodes)
}

pub async fn list_graph_edges_by_metadata(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    metadata_contains: &Value,
    group_read_roles: &[&str],
) -> Result<Vec<GraphEdge>> {
    let _ = load_accessible_graph(pool, actor, graph_id, group_read_roles).await?;
    let metadata_filter = api_metadata_to_db_json(metadata_contains)?;
    let rows = sqlx::query_as::<_, GraphEdgeRow>(
        r#"
        SELECT from_node_id, to_node_id, metadata
        FROM graph.edges
        WHERE graph_id = $1
          AND metadata @> $2::jsonb
        ORDER BY from_node_id ASC, to_node_id ASC
        "#,
    )
    .bind(graph_id.0)
    .bind(metadata_filter)
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to query graph edges by metadata", err))?;

    let mut edges = Vec::with_capacity(rows.len());
    for row in rows {
        let metadata = db_metadata_to_api_json(&row.metadata)
            .map_err(|err| db_metadata_decode_err("Failed to decode graph edge metadata", err))?;
        edges.push(GraphEdge {
            from_node_id: GraphNodeId(row.from_node_id),
            to_node_id: GraphNodeId(row.to_node_id),
            metadata,
        });
    }

    Ok(edges)
}

pub async fn delete_graph(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    group_delete_roles: &[&str],
) -> Result<()> {
    let normalized_roles = normalize_required_roles(group_delete_roles)?;

    let deleted = sqlx::query(
        r#"
        DELETE FROM graph.graphs
        WHERE id = $1
          AND (
              (owner_group_id IS NULL AND owner_user_id = $2)
              OR (
                  owner_group_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM auth.group_memberships gm
                      JOIN auth.groups grp
                        ON grp.id = gm.group_id
                      JOIN auth.users usr
                        ON usr.id = gm.user_id
                      WHERE gm.group_id = graph.graphs.owner_group_id
                        AND gm.user_id = $2
                        AND grp.active = TRUE
                        AND usr.active = TRUE
                        AND (
                            EXISTS (
                                SELECT 1
                                FROM auth.user_roles ur
                                WHERE ur.user_id = gm.user_id
                                  AND ur.scope = $4
                                  AND ur.scope_id IN (gm.group_id::text, $5)
                                  AND ur.role_name = ANY($3)
                            )
                            OR EXISTS (
                                SELECT 1
                                FROM auth.group_roles gr
                                WHERE gr.group_id = gm.group_id
                                  AND gr.scope = $4
                                  AND gr.scope_id = gm.group_id::text
                                  AND gr.role_name = ANY($3)
                            )
                        )
                  )
              )
          )
        "#,
    )
    .bind(graph_id.0)
    .bind(actor.0)
    .bind(&normalized_roles)
    .bind(permissions::graph_role_scope())
    .bind(permissions::graph_role_scope_id_global())
    .execute(pool)
    .await
    .map_err(|err| db_err("Failed to delete graph", err))?;

    if deleted.rows_affected() == 0 {
        return if graph_exists(pool, graph_id).await? {
            let context = load_graph_access_context(pool, graph_id).await?;
            Err(graph_access_denied_error(
                actor,
                graph_id,
                context,
                &normalized_roles,
            ))
        } else {
            Err(LibError::not_found(
                "Graph not found",
                anyhow!("graph {} not found", graph_id),
            ))
        };
    }

    Ok(())
}

async fn group_exists(pool: &PgPool, group_id: GroupId) -> Result<bool> {
    let exists: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM auth.groups
            WHERE id = $1
        )
        "#,
    )
    .bind(group_id.0)
    .fetch_one(pool)
    .await
    .map_err(|err| db_err("Failed to query group", err))?;

    Ok(exists.0)
}

fn normalize_roles(roles: &[String]) -> Vec<String> {
    let mut dedupe = HashSet::new();
    roles
        .iter()
        .map(|role| role.trim())
        .filter(|role| !role.is_empty())
        .filter(|role| dedupe.insert((*role).to_string()))
        .map(ToString::to_string)
        .collect()
}

fn normalize_known_graph_permission_roles(roles: &[String]) -> Result<Vec<String>> {
    let cleaned = normalize_roles(roles);
    let invalid_roles: Vec<&String> = cleaned
        .iter()
        .filter(|role| !permissions::is_graph_permission_role(role))
        .collect();
    if !invalid_roles.is_empty() {
        return Err(LibError::invalid(
            "One or more roles are not valid graph permission roles",
            anyhow!(
                "invalid graph permission roles: {}",
                invalid_roles
                    .iter()
                    .map(|role| role.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ),
        ));
    }

    Ok(cleaned)
}

pub async fn authorize_group_permission(
    pool: &PgPool,
    actor: UserId,
    group_id: GroupId,
    required_roles: &[&str],
    denied_message: &'static str,
) -> Result<()> {
    ensure_group_permission(pool, actor, group_id, required_roles, denied_message).await
}

pub async fn list_group_allowed_roles(pool: &PgPool, group_id: GroupId) -> Result<Vec<String>> {
    if !group_exists(pool, group_id).await? {
        return Err(LibError::not_found(
            "Group not found",
            anyhow!("group {} not found", group_id),
        ));
    }
    let role_scope_id = permissions::graph_role_scope_id_for_group(group_id);
    let known_roles: Vec<String> = permissions::all_graph_permission_roles()
        .iter()
        .map(|role| (*role).to_string())
        .collect();

    sqlx::query_scalar::<_, String>(
        r#"
        SELECT role_name
        FROM auth.group_roles
        WHERE group_id = $1
          AND scope = $2
          AND scope_id = $3
          AND role_name = ANY($4)
        ORDER BY role_name ASC
        "#,
    )
    .bind(group_id.0)
    .bind(permissions::graph_role_scope())
    .bind(role_scope_id)
    .bind(known_roles)
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to list allowed roles", err))
}

pub async fn set_group_allowed_roles(
    pool: &PgPool,
    group_id: GroupId,
    roles: &[String],
) -> Result<()> {
    if !group_exists(pool, group_id).await? {
        return Err(LibError::not_found(
            "Group not found",
            anyhow!("group {} not found", group_id),
        ));
    }

    let cleaned_roles = normalize_known_graph_permission_roles(roles)?;
    let known_roles: Vec<String> = permissions::all_graph_permission_roles()
        .iter()
        .map(|role| (*role).to_string())
        .collect();
    let role_scope_id = permissions::graph_role_scope_id_for_group(group_id);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;

    sqlx::query(
        r#"
        DELETE FROM auth.group_roles
        WHERE group_id = $1
          AND scope = $2
          AND scope_id = $3
          AND role_name = ANY($4)
        "#,
    )
    .bind(group_id.0)
    .bind(permissions::graph_role_scope())
    .bind(&role_scope_id)
    .bind(known_roles)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to clear allowed roles", err))?;

    for role in &cleaned_roles {
        sqlx::query(
            r#"
            INSERT INTO auth.group_roles (group_id, scope, scope_id, role_name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (group_id, scope, scope_id, role_name) DO NOTHING
            "#,
        )
        .bind(group_id.0)
        .bind(permissions::graph_role_scope())
        .bind(&role_scope_id)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(|err| db_err("Failed to save allowed roles", err))?;
    }

    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use subseq_auth::prelude::ApiErrorDetails;

    #[test]
    fn normalize_required_roles_trims_and_dedupes() {
        let roles = normalize_required_roles(&[" graph_read ", "graph_update", "graph_read"])
            .expect("roles should normalize");

        assert_eq!(
            roles,
            vec!["graph_read".to_string(), "graph_update".to_string()]
        );
    }

    #[test]
    fn normalize_required_roles_rejects_empty_sets() {
        let err = normalize_required_roles(&["", "  "]).expect_err("should reject empty role set");

        assert_eq!(err.kind, crate::error::ErrorKind::Forbidden);
        assert_eq!(err.code, "forbidden");
        assert_eq!(err.public, "Graph permissions are not configured");
    }

    #[test]
    fn graph_access_denied_error_includes_missing_scope_details_for_group_graphs() {
        let actor = UserId(Uuid::new_v4());
        let graph_id = GraphId(Uuid::new_v4());
        let group_id = Uuid::new_v4();
        let required_roles = vec!["graph_read".to_string(), "graph_update".to_string()];

        let err = graph_access_denied_error(
            actor,
            graph_id,
            Some(GraphAccessContextRow {
                owner_group_id: Some(group_id),
            }),
            &required_roles,
        );

        assert_eq!(err.kind, crate::error::ErrorKind::Forbidden);
        assert_eq!(err.code, "missing_scope_check");
        assert_eq!(err.public, "You do not have access to this graph");
        match err.details {
            Some(ApiErrorDetails::MissingScopeCheck {
                scope,
                scope_id,
                required_any_roles,
            }) => {
                assert_eq!(scope, permissions::graph_role_scope());
                assert_eq!(scope_id, group_id.to_string());
                assert_eq!(required_any_roles, required_roles);
            }
            other => panic!("expected missing scope details, got {:?}", other),
        }
    }

    #[test]
    fn graph_access_denied_error_stays_generic_without_group_scope() {
        let actor = UserId(Uuid::new_v4());
        let graph_id = GraphId(Uuid::new_v4());
        let required_roles = vec!["graph_read".to_string()];

        let err = graph_access_denied_error(
            actor,
            graph_id,
            Some(GraphAccessContextRow {
                owner_group_id: None,
            }),
            &required_roles,
        );

        assert_eq!(err.kind, crate::error::ErrorKind::Forbidden);
        assert_eq!(err.code, "forbidden");
        assert!(err.details.is_none());
    }

    #[test]
    fn update_graph_definition_node_updates_existing_when_id_matches() {
        let existing_id = GraphNodeId(Uuid::new_v4());
        let mut nodes = vec![GraphNode {
            id: existing_id,
            label: "old".to_string(),
            metadata: json!({"a": 1}),
        }];

        let payload = UpsertNodePayload {
            node_id: Some(existing_id),
            label: " updated ".to_string(),
            metadata: None,
            expected_updated_at: None,
        };

        let (node_id, inserted) =
            update_graph_definition_node(&mut nodes, &payload).expect("update should work");
        assert_eq!(node_id, existing_id);
        assert!(!inserted);
        assert_eq!(nodes[0].label, "updated");
        assert_eq!(nodes[0].metadata, json!({"a": 1}));
    }

    #[test]
    fn update_graph_definition_node_inserts_new_when_missing() {
        let mut nodes = Vec::new();
        let explicit_id = GraphNodeId(Uuid::new_v4());
        let payload = UpsertNodePayload {
            node_id: Some(explicit_id),
            label: "new".to_string(),
            metadata: Some(json!({"ext": "x"})),
            expected_updated_at: None,
        };

        let (node_id, inserted) =
            update_graph_definition_node(&mut nodes, &payload).expect("insert should work");
        assert_eq!(node_id, explicit_id);
        assert!(inserted);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].metadata, json!({"ext": "x"}));
    }

    #[test]
    fn update_graph_definition_node_canonicalizes_metadata_case() {
        let mut nodes = Vec::new();
        let explicit_id = GraphNodeId(Uuid::new_v4());
        let payload = UpsertNodePayload {
            node_id: Some(explicit_id),
            label: "new".to_string(),
            metadata: Some(json!({
                "external_id": "task-1",
                "nested_value": {
                    "task_id": "abc"
                }
            })),
            expected_updated_at: None,
        };

        let (_, inserted) =
            update_graph_definition_node(&mut nodes, &payload).expect("insert should work");
        assert!(inserted);
        assert_eq!(
            nodes[0].metadata,
            json!({
                "externalId": "task-1",
                "nestedValue": {
                    "taskId": "abc"
                }
            })
        );
    }

    #[test]
    fn update_graph_definition_node_rejects_metadata_key_collisions() {
        let mut nodes = Vec::new();
        let explicit_id = GraphNodeId(Uuid::new_v4());
        let payload = UpsertNodePayload {
            node_id: Some(explicit_id),
            label: "new".to_string(),
            metadata: Some(json!({
                "external_id": "a",
                "externalId": "b"
            })),
            expected_updated_at: None,
        };

        let err = update_graph_definition_node(&mut nodes, &payload)
            .expect_err("colliding metadata keys should fail");
        assert_eq!(
            err.public,
            "Metadata contains conflicting keys after normalization"
        );
    }

    #[test]
    fn apply_reparent_edges_preserves_metadata_when_parent_is_unchanged() {
        let parent = GraphNodeId(Uuid::new_v4());
        let child = GraphNodeId(Uuid::new_v4());
        let other_from = GraphNodeId(Uuid::new_v4());
        let other_to = GraphNodeId(Uuid::new_v4());
        let edges = vec![
            GraphEdge {
                from_node_id: parent,
                to_node_id: child,
                metadata: json!({"weight": 2}),
            },
            GraphEdge {
                from_node_id: other_from,
                to_node_id: other_to,
                metadata: json!({"kind": "other"}),
            },
        ];

        let updated = apply_reparent_edges(&edges, child, Some(parent), None);
        assert_eq!(updated.len(), 2);
        assert!(updated.iter().any(|edge| edge.from_node_id == parent
            && edge.to_node_id == child
            && edge.metadata == json!({"weight": 2})));
        assert!(updated.iter().any(|edge| edge.from_node_id == other_from
            && edge.to_node_id == other_to
            && edge.metadata == json!({"kind": "other"})));
    }

    #[test]
    fn apply_reparent_edges_can_reparent_tree_without_intermediate_violation() {
        let root = GraphNodeId(Uuid::new_v4());
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let nodes = vec![
            GraphNode {
                id: root,
                label: "root".to_string(),
                metadata: json!({}),
            },
            GraphNode {
                id: a,
                label: "a".to_string(),
                metadata: json!({}),
            },
            GraphNode {
                id: b,
                label: "b".to_string(),
                metadata: json!({}),
            },
            GraphNode {
                id: c,
                label: "c".to_string(),
                metadata: json!({}),
            },
        ];
        let edges = vec![
            GraphEdge {
                from_node_id: root,
                to_node_id: a,
                metadata: json!({}),
            },
            GraphEdge {
                from_node_id: root,
                to_node_id: b,
                metadata: json!({}),
            },
            GraphEdge {
                from_node_id: a,
                to_node_id: c,
                metadata: json!({}),
            },
        ];

        let updated = apply_reparent_edges(
            &edges,
            c,
            Some(b),
            Some(json!({"relationType": "subtaskOf"})),
        );
        let violations =
            crate::invariants::graph_invariant_violations(GraphKind::Tree, &nodes, &updated);

        assert!(violations.is_empty());
        assert!(updated.iter().any(|edge| edge.from_node_id == b
            && edge.to_node_id == c
            && edge.metadata == json!({"relationType": "subtaskOf"})));
    }

    #[test]
    fn apply_reparent_edges_detach_reports_tree_violations() {
        let root = GraphNodeId(Uuid::new_v4());
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let nodes = vec![
            GraphNode {
                id: root,
                label: "root".to_string(),
                metadata: json!({}),
            },
            GraphNode {
                id: a,
                label: "a".to_string(),
                metadata: json!({}),
            },
            GraphNode {
                id: b,
                label: "b".to_string(),
                metadata: json!({}),
            },
            GraphNode {
                id: c,
                label: "c".to_string(),
                metadata: json!({}),
            },
        ];
        let edges = vec![
            GraphEdge {
                from_node_id: root,
                to_node_id: a,
                metadata: json!({}),
            },
            GraphEdge {
                from_node_id: root,
                to_node_id: b,
                metadata: json!({}),
            },
            GraphEdge {
                from_node_id: a,
                to_node_id: c,
                metadata: json!({}),
            },
        ];

        let updated = apply_reparent_edges(&edges, c, None, None);
        let violations =
            crate::invariants::graph_invariant_violations(GraphKind::Tree, &nodes, &updated);

        assert!(!violations.is_empty());
        assert!(violations.iter().any(|violation| {
            matches!(
                violation,
                crate::models::GraphInvariantViolation::InvalidRootCount { .. }
                    | crate::models::GraphInvariantViolation::DisconnectedTree { .. }
            )
        }));
    }
}
