use anyhow::anyhow;
use once_cell::sync::Lazy;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use subseq_auth::group_id::GroupId;
use subseq_auth::user_id::UserId;

use crate::error::{LibError, Result};
use crate::models::{
    CreateGraphPayload, DirectedGraph, GraphDefinition, GraphEdge, GraphId, GraphNode, GraphNodeId,
    GraphSummary, UpdateGraphPayload,
};

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

impl From<GraphSummaryRow> for GraphSummary {
    fn from(value: GraphSummaryRow) -> Self {
        Self {
            id: GraphId(value.id),
            owner_user_id: UserId(value.owner_user_id),
            owner_group_id: value.owner_group_id.map(GroupId),
            name: value.name,
            description: value.description,
            created_at: value.created_at,
            updated_at: value.updated_at,
            node_count: value.node_count,
            edge_count: value.edge_count,
        }
    }
}

fn hydrate_graph(
    row: GraphRow,
    nodes: Vec<GraphNodeRow>,
    edges: Vec<GraphEdgeRow>,
) -> DirectedGraph {
    DirectedGraph {
        id: GraphId(row.id),
        owner_user_id: UserId(row.owner_user_id),
        owner_group_id: row.owner_group_id.map(GroupId),
        name: row.name,
        description: row.description,
        metadata: row.metadata,
        created_at: row.created_at,
        updated_at: row.updated_at,
        nodes: nodes
            .into_iter()
            .map(|node| GraphNode {
                id: GraphNodeId(node.id),
                label: node.label,
                metadata: node.metadata,
            })
            .collect(),
        edges: edges
            .into_iter()
            .map(|edge| GraphEdge {
                from_node_id: GraphNodeId(edge.from_node_id),
                to_node_id: GraphNodeId(edge.to_node_id),
                metadata: edge.metadata,
            })
            .collect(),
    }
}

fn db_err(public: &'static str, err: sqlx::Error) -> LibError {
    LibError::database(public, anyhow!(err))
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

async fn ensure_group_member(pool: &PgPool, actor: UserId, group_id: GroupId) -> Result<()> {
    let is_member: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM auth.group_memberships
            WHERE group_id = $1
              AND user_id = $2
        )
        "#,
    )
    .bind(group_id.0)
    .bind(actor.0)
    .fetch_one(pool)
    .await
    .map_err(|err| db_err("Failed to query group membership", err))?;

    if is_member.0 {
        Ok(())
    } else {
        Err(LibError::forbidden(
            "You are not a member of this group",
            anyhow!("user {} is not in group {}", actor, group_id),
        ))
    }
}

async fn load_accessible_graph(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
) -> Result<GraphRow> {
    let row = sqlx::query_as::<_, GraphRow>(
        r#"
        SELECT
            g.id,
            g.owner_user_id,
            g.owner_group_id,
            g.name,
            g.description,
            g.metadata,
            g.created_at,
            g.updated_at
        FROM graph.graphs g
        WHERE g.id = $1
          AND (
              g.owner_user_id = $2
              OR (
                  g.owner_group_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM auth.group_memberships gm
                      WHERE gm.group_id = g.owner_group_id
                        AND gm.user_id = $2
                  )
              )
          )
        LIMIT 1
        "#,
    )
    .bind(graph_id.0)
    .bind(actor.0)
    .fetch_optional(pool)
    .await
    .map_err(|err| db_err("Failed to query graph", err))?;

    if let Some(row) = row {
        Ok(row)
    } else if graph_exists(pool, graph_id).await? {
        Err(LibError::forbidden(
            "You do not have access to this graph",
            anyhow!("graph {} access denied for user {}", graph_id, actor),
        ))
    } else {
        Err(LibError::not_found(
            "Graph not found",
            anyhow!("graph {} not found", graph_id),
        ))
    }
}

async fn write_graph_contents(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    graph_id: GraphId,
    definition: &GraphDefinition,
) -> Result<()> {
    for node in &definition.nodes {
        sqlx::query(
            r#"
            INSERT INTO graph.nodes (id, graph_id, label, metadata)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(node.id.0)
        .bind(graph_id.0)
        .bind(&node.label)
        .bind(&node.metadata)
        .execute(&mut **tx)
        .await
        .map_err(|err| db_err("Failed to write graph nodes", err))?;
    }

    for edge in &definition.edges {
        sqlx::query(
            r#"
            INSERT INTO graph.edges (graph_id, from_node_id, to_node_id, metadata)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(graph_id.0)
        .bind(edge.from_node_id.0)
        .bind(edge.to_node_id.0)
        .bind(&edge.metadata)
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
) -> Result<DirectedGraph> {
    let definition = payload.normalize()?;
    if let Some(group_id) = definition.owner_group_id {
        ensure_group_member(pool, actor, group_id).await?;
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
            name,
            description,
            metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(graph_id.0)
    .bind(actor.0)
    .bind(owner_group_id)
    .bind(&definition.name)
    .bind(&definition.description)
    .bind(&definition.metadata)
    .execute(&mut *tx)
    .await
    .map_err(|err| db_err("Failed to create graph", err))?;

    write_graph_contents(&mut tx, graph_id, &definition).await?;

    tx.commit()
        .await
        .map_err(|err| db_err("Failed to commit transaction", err))?;

    get_graph(pool, actor, graph_id).await
}

pub async fn get_graph(pool: &PgPool, actor: UserId, graph_id: GraphId) -> Result<DirectedGraph> {
    let graph = load_accessible_graph(pool, actor, graph_id).await?;
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

    Ok(hydrate_graph(graph, nodes, edges))
}

pub async fn list_graphs(
    pool: &PgPool,
    actor: UserId,
    page: u32,
    limit: u32,
) -> Result<Vec<GraphSummary>> {
    let offset = (page.saturating_sub(1) as i64).saturating_mul(limit as i64);

    let rows = sqlx::query_as::<_, GraphSummaryRow>(
        r#"
        SELECT
            g.id,
            g.owner_user_id,
            g.owner_group_id,
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
            g.owner_user_id = $1
            OR (
                g.owner_group_id IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM auth.group_memberships gm
                    WHERE gm.group_id = g.owner_group_id
                      AND gm.user_id = $1
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
    .fetch_all(pool)
    .await
    .map_err(|err| db_err("Failed to list graphs", err))?;

    Ok(rows.into_iter().map(GraphSummary::from).collect())
}

pub async fn update_graph(
    pool: &PgPool,
    actor: UserId,
    graph_id: GraphId,
    payload: UpdateGraphPayload,
) -> Result<DirectedGraph> {
    let definition = payload.normalize()?;
    let _graph = load_accessible_graph(pool, actor, graph_id).await?;

    if let Some(group_id) = definition.owner_group_id {
        ensure_group_member(pool, actor, group_id).await?;
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| db_err("Failed to start transaction", err))?;

    sqlx::query(
        r#"
        UPDATE graph.graphs
        SET owner_group_id = $1,
            name = $2,
            description = $3,
            metadata = $4,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $5
        "#,
    )
    .bind(definition.owner_group_id.map(|id| id.0))
    .bind(&definition.name)
    .bind(&definition.description)
    .bind(&definition.metadata)
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

    get_graph(pool, actor, graph_id).await
}

pub async fn delete_graph(pool: &PgPool, actor: UserId, graph_id: GraphId) -> Result<()> {
    let _graph = load_accessible_graph(pool, actor, graph_id).await?;

    sqlx::query(
        r#"
        DELETE FROM graph.graphs
        WHERE id = $1
        "#,
    )
    .bind(graph_id.0)
    .execute(pool)
    .await
    .map_err(|err| db_err("Failed to delete graph", err))?;

    Ok(())
}
