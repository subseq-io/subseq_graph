use std::collections::HashSet;
use std::sync::Arc;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use subseq_auth::group_id::GroupId;
use subseq_auth::user_id::UserId;

use crate::db;
use crate::error::{LibError, Result};
use crate::models::{
    AddEdgePayload, CreateGraphPayload, DirectedGraph, GraphEdge, GraphId, GraphNode, GraphNodeId,
    GraphSummary, GroupGraphPermissions, GuardedUpdateGraphPayload, ListGraphsQuery,
    MetadataFilterPayload, NewGraphEdge, NewGraphNode, Paged, RemoveEdgePayload, RemoveNodePayload,
    ReparentNodePayload, UpdateGraphPayload, UpdateGroupGraphPermissionsPayload,
    UpsertEdgeMetadataPayload, UpsertNodePayload,
};
use crate::permissions;

/// MCP-friendly high-level graph actions.
///
/// Callers must provide a trusted `actor` sourced from validated auth/session state,
/// not from model/tool arguments.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum GraphOperation {
    Create {
        payload: CreateGraphPayload,
    },
    Extend {
        graph_id: GraphId,
        payload: ExtendGraphPayload,
    },
    Replace {
        graph_id: GraphId,
        payload: UpdateGraphPayload,
    },
    ReplaceGuarded {
        graph_id: GraphId,
        payload: GuardedUpdateGraphPayload,
    },
    Get {
        graph_id: GraphId,
    },
    List {
        query: ListGraphsQuery,
    },
    Delete {
        graph_id: GraphId,
    },
    AddEdge {
        graph_id: GraphId,
        payload: AddEdgePayload,
    },
    RemoveEdge {
        graph_id: GraphId,
        payload: RemoveEdgePayload,
    },
    UpsertEdgeMetadata {
        graph_id: GraphId,
        payload: UpsertEdgeMetadataPayload,
    },
    UpsertNode {
        graph_id: GraphId,
        payload: UpsertNodePayload,
    },
    RemoveNode {
        graph_id: GraphId,
        payload: RemoveNodePayload,
    },
    ReparentNode {
        graph_id: GraphId,
        payload: ReparentNodePayload,
    },
    FindNodeByExternalId {
        graph_id: GraphId,
        external_id: String,
    },
    QueryNodesByMetadata {
        graph_id: GraphId,
        payload: MetadataFilterPayload,
    },
    QueryEdgesByMetadata {
        graph_id: GraphId,
        payload: MetadataFilterPayload,
    },
    IncidentEdgesForNode {
        graph_id: GraphId,
        node_id: GraphNodeId,
    },
    IncidentEdgesForExternalId {
        graph_id: GraphId,
        external_id: String,
    },
    GetGroupPermissions {
        group_id: GroupId,
    },
    SetGroupPermissions {
        group_id: GroupId,
        payload: UpdateGroupGraphPermissionsPayload,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendGraphPayload {
    pub nodes: Vec<NewGraphNode>,
    pub edges: Vec<NewGraphEdge>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum GraphOperationResult {
    Graph {
        graph: DirectedGraph,
    },
    Node {
        node: GraphNode,
    },
    Nodes {
        nodes: Vec<GraphNode>,
    },
    Edges {
        edges: Vec<GraphEdge>,
    },
    GraphsPage {
        page: u32,
        limit: u32,
        items: Vec<GraphSummary>,
    },
    GroupPermissions {
        permissions: GroupGraphPermissions,
    },
    Deleted,
}

#[derive(Clone)]
pub struct GraphOperations {
    pool: Arc<PgPool>,
}

impl GraphOperations {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub fn from_pool(pool: &PgPool) -> Self {
        Self {
            pool: Arc::new(pool.clone()),
        }
    }

    pub fn pool(&self) -> Arc<PgPool> {
        Arc::clone(&self.pool)
    }

    pub async fn execute(
        &self,
        actor: UserId,
        operation: GraphOperation,
    ) -> Result<GraphOperationResult> {
        match operation {
            GraphOperation::Create { payload } => {
                let graph = self.create_graph(actor, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::Extend { graph_id, payload } => {
                let graph = self.extend_graph(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::Replace { graph_id, payload } => {
                let graph = self.replace_graph(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::ReplaceGuarded { graph_id, payload } => {
                let graph = self.replace_graph_guarded(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::Get { graph_id } => {
                let graph = self.get_graph(actor, graph_id).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::List { query } => {
                let page = self.list_graphs(actor, query).await?;
                Ok(GraphOperationResult::GraphsPage {
                    page: page.page,
                    limit: page.limit,
                    items: page.items,
                })
            }
            GraphOperation::Delete { graph_id } => {
                self.delete_graph(actor, graph_id).await?;
                Ok(GraphOperationResult::Deleted)
            }
            GraphOperation::AddEdge { graph_id, payload } => {
                let graph = self.add_edge(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::RemoveEdge { graph_id, payload } => {
                let graph = self.remove_edge(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::UpsertEdgeMetadata { graph_id, payload } => {
                let graph = self.upsert_edge_metadata(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::UpsertNode { graph_id, payload } => {
                let graph = self.upsert_node(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::RemoveNode { graph_id, payload } => {
                let graph = self.remove_node(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::ReparentNode { graph_id, payload } => {
                let graph = self.reparent_node(actor, graph_id, payload).await?;
                Ok(GraphOperationResult::Graph { graph })
            }
            GraphOperation::FindNodeByExternalId {
                graph_id,
                external_id,
            } => {
                let node = self
                    .find_node_by_external_id(actor, graph_id, &external_id)
                    .await?;
                Ok(GraphOperationResult::Node { node })
            }
            GraphOperation::QueryNodesByMetadata { graph_id, payload } => {
                let nodes = self
                    .query_nodes_by_metadata(actor, graph_id, &payload.metadata_contains)
                    .await?;
                Ok(GraphOperationResult::Nodes { nodes })
            }
            GraphOperation::QueryEdgesByMetadata { graph_id, payload } => {
                let edges = self
                    .query_edges_by_metadata(actor, graph_id, &payload.metadata_contains)
                    .await?;
                Ok(GraphOperationResult::Edges { edges })
            }
            GraphOperation::IncidentEdgesForNode { graph_id, node_id } => {
                let edges = self
                    .incident_edges_for_node(actor, graph_id, node_id)
                    .await?;
                Ok(GraphOperationResult::Edges { edges })
            }
            GraphOperation::IncidentEdgesForExternalId {
                graph_id,
                external_id,
            } => {
                let edges = self
                    .incident_edges_for_external_id(actor, graph_id, &external_id)
                    .await?;
                Ok(GraphOperationResult::Edges { edges })
            }
            GraphOperation::GetGroupPermissions { group_id } => {
                let permissions = self.get_group_permissions(actor, group_id).await?;
                Ok(GraphOperationResult::GroupPermissions { permissions })
            }
            GraphOperation::SetGroupPermissions { group_id, payload } => {
                let permissions = self.set_group_permissions(actor, group_id, payload).await?;
                Ok(GraphOperationResult::GroupPermissions { permissions })
            }
        }
    }

    pub async fn create_graph(
        &self,
        actor: UserId,
        payload: CreateGraphPayload,
    ) -> Result<DirectedGraph> {
        db::create_graph(
            &self.pool,
            actor,
            payload,
            permissions::graph_create_access_roles(),
        )
        .await
    }

    pub async fn extend_graph(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: ExtendGraphPayload,
    ) -> Result<DirectedGraph> {
        let existing = db::get_graph(
            &self.pool,
            actor,
            graph_id,
            permissions::graph_update_access_roles(),
        )
        .await?;
        let update_payload = merge_graph_additions(&existing, payload)?;
        db::update_graph(
            &self.pool,
            actor,
            graph_id,
            update_payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn replace_graph(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: UpdateGraphPayload,
    ) -> Result<DirectedGraph> {
        db::update_graph(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn replace_graph_guarded(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: GuardedUpdateGraphPayload,
    ) -> Result<DirectedGraph> {
        db::update_graph_with_guard(
            &self.pool,
            actor,
            graph_id,
            payload.graph,
            payload.expected_updated_at,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn get_graph(&self, actor: UserId, graph_id: GraphId) -> Result<DirectedGraph> {
        db::get_graph(
            &self.pool,
            actor,
            graph_id,
            permissions::graph_read_access_roles(),
        )
        .await
    }

    pub async fn list_graphs(
        &self,
        actor: UserId,
        query: ListGraphsQuery,
    ) -> Result<Paged<GraphSummary>> {
        let (page, limit) = query.pagination();
        let items = db::list_graphs(
            &self.pool,
            actor,
            page,
            limit,
            permissions::graph_read_access_roles(),
        )
        .await?;
        Ok(Paged { page, limit, items })
    }

    pub async fn delete_graph(&self, actor: UserId, graph_id: GraphId) -> Result<()> {
        db::delete_graph(
            &self.pool,
            actor,
            graph_id,
            permissions::graph_delete_access_roles(),
        )
        .await
    }

    pub async fn add_edge(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: AddEdgePayload,
    ) -> Result<DirectedGraph> {
        db::add_edge(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn remove_edge(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: RemoveEdgePayload,
    ) -> Result<DirectedGraph> {
        db::remove_edge(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn upsert_edge_metadata(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: UpsertEdgeMetadataPayload,
    ) -> Result<DirectedGraph> {
        db::upsert_edge_metadata(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn upsert_node(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: UpsertNodePayload,
    ) -> Result<DirectedGraph> {
        db::upsert_node(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn remove_node(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: RemoveNodePayload,
    ) -> Result<DirectedGraph> {
        db::remove_node(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn reparent_node(
        &self,
        actor: UserId,
        graph_id: GraphId,
        payload: ReparentNodePayload,
    ) -> Result<DirectedGraph> {
        db::reparent_node(
            &self.pool,
            actor,
            graph_id,
            payload,
            permissions::graph_update_access_roles(),
        )
        .await
    }

    pub async fn find_node_by_external_id(
        &self,
        actor: UserId,
        graph_id: GraphId,
        external_id: &str,
    ) -> Result<GraphNode> {
        db::find_node_by_external_id(
            &self.pool,
            actor,
            graph_id,
            external_id,
            permissions::graph_read_access_roles(),
        )
        .await?
        .ok_or_else(|| {
            LibError::not_found(
                "Node not found",
                anyhow!(
                    "external_id '{}' not found in graph {}",
                    external_id,
                    graph_id
                ),
            )
        })
    }

    pub async fn query_nodes_by_metadata(
        &self,
        actor: UserId,
        graph_id: GraphId,
        metadata_contains: &Value,
    ) -> Result<Vec<GraphNode>> {
        db::list_graph_nodes_by_metadata(
            &self.pool,
            actor,
            graph_id,
            metadata_contains,
            permissions::graph_read_access_roles(),
        )
        .await
    }

    pub async fn query_edges_by_metadata(
        &self,
        actor: UserId,
        graph_id: GraphId,
        metadata_contains: &Value,
    ) -> Result<Vec<GraphEdge>> {
        db::list_graph_edges_by_metadata(
            &self.pool,
            actor,
            graph_id,
            metadata_contains,
            permissions::graph_read_access_roles(),
        )
        .await
    }

    pub async fn incident_edges_for_node(
        &self,
        actor: UserId,
        graph_id: GraphId,
        node_id: GraphNodeId,
    ) -> Result<Vec<GraphEdge>> {
        db::list_incident_edges_for_node(
            &self.pool,
            actor,
            graph_id,
            node_id,
            permissions::graph_read_access_roles(),
        )
        .await
    }

    pub async fn incident_edges_for_external_id(
        &self,
        actor: UserId,
        graph_id: GraphId,
        external_id: &str,
    ) -> Result<Vec<GraphEdge>> {
        db::list_incident_edges_for_external_id(
            &self.pool,
            actor,
            graph_id,
            external_id,
            permissions::graph_read_access_roles(),
        )
        .await
    }

    pub async fn get_group_permissions(
        &self,
        actor: UserId,
        group_id: GroupId,
    ) -> Result<GroupGraphPermissions> {
        db::authorize_group_permission(
            &self.pool,
            actor,
            group_id,
            permissions::graph_permissions_read_access_roles(),
            "You do not have permission to view graph permissions for this group",
        )
        .await?;
        let allowed_roles = db::list_group_allowed_roles(&self.pool, group_id).await?;
        Ok(GroupGraphPermissions {
            group_id,
            allowed_roles,
        })
    }

    pub async fn set_group_permissions(
        &self,
        actor: UserId,
        group_id: GroupId,
        payload: UpdateGroupGraphPermissionsPayload,
    ) -> Result<GroupGraphPermissions> {
        db::authorize_group_permission(
            &self.pool,
            actor,
            group_id,
            permissions::graph_permissions_update_access_roles(),
            "You do not have permission to manage graph permissions for this group",
        )
        .await?;
        db::set_group_allowed_roles(&self.pool, group_id, &payload.allowed_roles).await?;
        let allowed_roles = db::list_group_allowed_roles(&self.pool, group_id).await?;
        Ok(GroupGraphPermissions {
            group_id,
            allowed_roles,
        })
    }
}

fn merge_graph_additions(
    existing: &DirectedGraph,
    payload: ExtendGraphPayload,
) -> Result<UpdateGraphPayload> {
    let mut node_ids: HashSet<GraphNodeId> = existing.nodes.iter().map(|node| node.id).collect();
    let mut nodes = existing
        .nodes
        .iter()
        .map(|node| NewGraphNode {
            id: Some(node.id),
            label: node.label.clone(),
            metadata: Some(node.metadata.clone()),
        })
        .collect::<Vec<_>>();

    for node in payload.nodes {
        let node_id = node.id.unwrap_or_else(|| GraphNodeId(Uuid::new_v4()));
        if !node_ids.insert(node_id) {
            return Err(LibError::invalid(
                "Node ID already exists in graph",
                anyhow!("duplicate node id {}", node_id),
            ));
        }
        let label = node.label.trim().to_string();
        if label.is_empty() {
            return Err(LibError::invalid(
                "Node label is required",
                anyhow!("node {} had empty label", node_id),
            ));
        }

        nodes.push(NewGraphNode {
            id: Some(node_id),
            label,
            metadata: Some(node.metadata.unwrap_or_else(|| json!({}))),
        });
    }

    let mut seen_edges = HashSet::new();
    let mut edges = Vec::with_capacity(existing.edges.len() + payload.edges.len());
    for edge in &existing.edges {
        seen_edges.insert((edge.from_node_id, edge.to_node_id));
        edges.push(NewGraphEdge {
            from_node_id: edge.from_node_id,
            to_node_id: edge.to_node_id,
            metadata: Some(edge.metadata.clone()),
        });
    }

    for edge in payload.edges {
        if !node_ids.contains(&edge.from_node_id) {
            return Err(LibError::invalid(
                "Edge source node not found",
                anyhow!("missing from_node_id {}", edge.from_node_id),
            ));
        }
        if !node_ids.contains(&edge.to_node_id) {
            return Err(LibError::invalid(
                "Edge destination node not found",
                anyhow!("missing to_node_id {}", edge.to_node_id),
            ));
        }
        if !seen_edges.insert((edge.from_node_id, edge.to_node_id)) {
            continue;
        }

        edges.push(NewGraphEdge {
            from_node_id: edge.from_node_id,
            to_node_id: edge.to_node_id,
            metadata: Some(edge.metadata.unwrap_or_else(|| json!({}))),
        });
    }

    Ok(UpdateGraphPayload {
        kind: existing.kind,
        name: existing.name.clone(),
        description: existing.description.clone(),
        metadata: Some(existing.metadata.clone()),
        owner_group_id: existing.owner_group_id,
        nodes,
        edges,
    })
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;
    use serde_json::json;

    use super::*;
    use crate::models::{GraphEdge, GraphKind, GraphNode};

    fn sample_graph() -> (DirectedGraph, GraphNodeId, GraphNodeId) {
        let n1 = GraphNodeId(Uuid::new_v4());
        let n2 = GraphNodeId(Uuid::new_v4());
        let now = NaiveDate::from_ymd_opt(2026, 1, 1)
            .expect("valid date")
            .and_hms_opt(0, 0, 0)
            .expect("valid datetime");

        (
            DirectedGraph {
                id: GraphId(Uuid::new_v4()),
                owner_user_id: UserId(Uuid::new_v4()),
                owner_group_id: Some(GroupId(Uuid::new_v4())),
                kind: GraphKind::Directed,
                name: "Roadmap".to_string(),
                description: Some("planning".to_string()),
                metadata: json!({"source": "test"}),
                created_at: now,
                updated_at: now,
                nodes: vec![
                    GraphNode {
                        id: n1,
                        label: "start".to_string(),
                        metadata: json!({}),
                    },
                    GraphNode {
                        id: n2,
                        label: "finish".to_string(),
                        metadata: json!({}),
                    },
                ],
                edges: vec![GraphEdge {
                    from_node_id: n1,
                    to_node_id: n2,
                    metadata: json!({"kind": "existing"}),
                }],
            },
            n1,
            n2,
        )
    }

    #[test]
    fn merge_graph_additions_adds_nodes_and_edges() {
        let (graph, n1, n2) = sample_graph();
        let n3 = GraphNodeId(Uuid::new_v4());

        let merged = merge_graph_additions(
            &graph,
            ExtendGraphPayload {
                nodes: vec![NewGraphNode {
                    id: Some(n3),
                    label: "extra".to_string(),
                    metadata: None,
                }],
                edges: vec![
                    NewGraphEdge {
                        from_node_id: n2,
                        to_node_id: n3,
                        metadata: None,
                    },
                    NewGraphEdge {
                        from_node_id: n1,
                        to_node_id: n2,
                        metadata: Some(json!({"ignored": true})),
                    },
                ],
            },
        )
        .expect("merge should succeed");

        assert_eq!(merged.nodes.len(), 3);
        assert_eq!(merged.edges.len(), 2);
        assert!(merged.nodes.iter().any(|node| node.id == Some(n3)));
        assert!(merged.edges.iter().any(|edge| {
            edge.from_node_id == n2 && edge.to_node_id == n3 && edge.metadata == Some(json!({}))
        }));
    }

    #[test]
    fn merge_graph_additions_rejects_existing_node_id() {
        let (graph, existing_node_id, _) = sample_graph();

        let err = merge_graph_additions(
            &graph,
            ExtendGraphPayload {
                nodes: vec![NewGraphNode {
                    id: Some(existing_node_id),
                    label: "duplicate".to_string(),
                    metadata: None,
                }],
                edges: vec![],
            },
        )
        .expect_err("duplicate node id should fail");

        assert_eq!(err.public, "Node ID already exists in graph");
    }

    #[test]
    fn merge_graph_additions_rejects_unknown_edge_nodes() {
        let (graph, existing_node_id, _) = sample_graph();
        let missing = GraphNodeId(Uuid::new_v4());

        let err = merge_graph_additions(
            &graph,
            ExtendGraphPayload {
                nodes: vec![],
                edges: vec![NewGraphEdge {
                    from_node_id: existing_node_id,
                    to_node_id: missing,
                    metadata: None,
                }],
            },
        )
        .expect_err("missing destination node should fail");

        assert_eq!(err.public, "Edge destination node not found");
    }

    #[test]
    fn merge_graph_additions_trims_labels_and_defaults_metadata() {
        let (graph, _, n2) = sample_graph();
        let n3 = GraphNodeId(Uuid::new_v4());

        let merged = merge_graph_additions(
            &graph,
            ExtendGraphPayload {
                nodes: vec![NewGraphNode {
                    id: Some(n3),
                    label: "  with spaces  ".to_string(),
                    metadata: None,
                }],
                edges: vec![NewGraphEdge {
                    from_node_id: n2,
                    to_node_id: n3,
                    metadata: None,
                }],
            },
        )
        .expect("merge should succeed");

        let added = merged
            .nodes
            .into_iter()
            .find(|node| node.id == Some(n3))
            .expect("added node should exist");
        assert_eq!(added.label, "with spaces");
        assert_eq!(added.metadata, Some(json!({})));
    }

    #[test]
    fn merge_graph_additions_can_trigger_kind_invariant_failure_on_normalize() {
        let (mut graph, n1, n2) = sample_graph();
        graph.kind = GraphKind::Dag;

        let merged = merge_graph_additions(
            &graph,
            ExtendGraphPayload {
                nodes: vec![],
                edges: vec![NewGraphEdge {
                    from_node_id: n2,
                    to_node_id: n1,
                    metadata: None,
                }],
            },
        )
        .expect("merge should produce payload");

        let err = merged
            .normalize()
            .expect_err("dag back-edge should fail invariant checks");
        assert_eq!(err.code, "graph_dag_cycle");
    }
}
