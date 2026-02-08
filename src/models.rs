use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subseq_auth::group_id::GroupId;
use subseq_auth::user_id::UserId;
use uuid::Uuid;

use crate::error::{LibError, Result};
use crate::invariants;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GraphKind {
    Tree,
    Dag,
    #[default]
    Directed,
}

impl GraphKind {
    pub const fn as_db_value(self) -> &'static str {
        match self {
            GraphKind::Tree => "tree",
            GraphKind::Dag => "dag",
            GraphKind::Directed => "directed",
        }
    }

    pub fn from_db_value(value: &str) -> Option<Self> {
        match value {
            "tree" => Some(GraphKind::Tree),
            "dag" => Some(GraphKind::Dag),
            "directed" => Some(GraphKind::Directed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct GraphId(pub Uuid);

impl fmt::Display for GraphId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for GraphId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

impl From<Uuid> for GraphId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct GraphNodeId(pub Uuid);

impl fmt::Display for GraphNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for GraphNodeId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

impl From<Uuid> for GraphNodeId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: GraphNodeId,
    pub label: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub from_node_id: GraphNodeId,
    pub to_node_id: GraphNodeId,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GraphInvariantViolation {
    UnknownNodeReference {
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
        missing_node_id: GraphNodeId,
    },
    SelfLoop {
        node_id: GraphNodeId,
    },
    CycleDetected,
    InDegreeExceeded {
        node_id: GraphNodeId,
        in_degree: usize,
    },
    InvalidRootCount {
        root_count: usize,
    },
    DisconnectedTree {
        unreachable_node_ids: Vec<GraphNodeId>,
    },
}

impl GraphInvariantViolation {
    pub const fn error_code(&self, kind: GraphKind) -> &'static str {
        match (kind, self) {
            (_, GraphInvariantViolation::UnknownNodeReference { .. }) => {
                "graph_unknown_node_reference"
            }
            (_, GraphInvariantViolation::SelfLoop { .. }) => "graph_self_loop_violation",
            (GraphKind::Tree, GraphInvariantViolation::CycleDetected) => "graph_tree_cycle",
            (GraphKind::Dag, GraphInvariantViolation::CycleDetected) => "graph_dag_cycle",
            (GraphKind::Directed, GraphInvariantViolation::CycleDetected) => "graph_cycle",
            (GraphKind::Tree, GraphInvariantViolation::InDegreeExceeded { .. }) => {
                "graph_tree_indegree_exceeded"
            }
            (_, GraphInvariantViolation::InDegreeExceeded { .. }) => "graph_indegree_exceeded",
            (GraphKind::Tree, GraphInvariantViolation::InvalidRootCount { .. }) => {
                "graph_tree_root_count"
            }
            (_, GraphInvariantViolation::InvalidRootCount { .. }) => "graph_invalid_root_count",
            (GraphKind::Tree, GraphInvariantViolation::DisconnectedTree { .. }) => {
                "graph_tree_disconnected"
            }
            (_, GraphInvariantViolation::DisconnectedTree { .. }) => "graph_disconnected",
        }
    }

    pub const fn public_message(&self, kind: GraphKind) -> &'static str {
        match (kind, self) {
            (_, GraphInvariantViolation::UnknownNodeReference { .. }) => {
                "Edge references a node that does not exist"
            }
            (_, GraphInvariantViolation::SelfLoop { .. }) => {
                "Self-loop edges are not allowed for this graph kind"
            }
            (GraphKind::Tree, GraphInvariantViolation::CycleDetected) => {
                "Tree graphs must be acyclic"
            }
            (GraphKind::Dag, GraphInvariantViolation::CycleDetected) => {
                "DAG graphs must be acyclic"
            }
            (_, GraphInvariantViolation::CycleDetected) => "Graph must be acyclic",
            (GraphKind::Tree, GraphInvariantViolation::InDegreeExceeded { .. }) => {
                "Tree nodes cannot have more than one incoming edge"
            }
            (_, GraphInvariantViolation::InDegreeExceeded { .. }) => {
                "Node in-degree exceeds allowed maximum"
            }
            (GraphKind::Tree, GraphInvariantViolation::InvalidRootCount { .. }) => {
                "Tree graphs must have exactly one root node"
            }
            (_, GraphInvariantViolation::InvalidRootCount { .. }) => "Graph root count is invalid",
            (GraphKind::Tree, GraphInvariantViolation::DisconnectedTree { .. }) => {
                "Tree graphs must be rooted and connected"
            }
            (_, GraphInvariantViolation::DisconnectedTree { .. }) => "Graph is disconnected",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateGraphEdgesPayload {
    pub kind: GraphKind,
    pub nodes: Vec<NewGraphNode>,
    pub edges: Vec<NewGraphEdge>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateGraphEdgesResponse {
    pub valid: bool,
    pub violations: Vec<GraphInvariantViolation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeMutationPayload {
    pub from_node_id: GraphNodeId,
    pub to_node_id: GraphNodeId,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeMutationCheckResponse {
    pub valid: bool,
    pub would_introduce_violation: bool,
    pub would_isolate_subgraph: bool,
    pub violations: Vec<GraphInvariantViolation>,
}

#[derive(Debug, Clone)]
pub struct GraphInvariantInput {
    pub kind: GraphKind,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectedGraph {
    pub id: GraphId,
    pub owner_user_id: UserId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_group_id: Option<GroupId>,
    pub kind: GraphKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub metadata: Value,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphSummary {
    pub id: GraphId,
    pub owner_user_id: UserId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_group_id: Option<GroupId>,
    pub kind: GraphKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub node_count: i64,
    pub edge_count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Paged<T> {
    pub page: u32,
    pub limit: u32,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewGraphNode {
    pub id: Option<GraphNodeId>,
    pub label: String,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewGraphEdge {
    pub from_node_id: GraphNodeId,
    pub to_node_id: GraphNodeId,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGraphPayload {
    pub kind: GraphKind,
    pub name: String,
    pub description: Option<String>,
    pub metadata: Option<Value>,
    pub owner_group_id: Option<GroupId>,
    pub nodes: Vec<NewGraphNode>,
    pub edges: Vec<NewGraphEdge>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGraphPayload {
    pub kind: GraphKind,
    pub name: String,
    pub description: Option<String>,
    pub metadata: Option<Value>,
    pub owner_group_id: Option<GroupId>,
    pub nodes: Vec<NewGraphNode>,
    pub edges: Vec<NewGraphEdge>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListGraphsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupGraphPermissionsPayload {
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupGraphPermissions {
    pub group_id: GroupId,
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GraphDefinition {
    pub kind: GraphKind,
    pub name: String,
    pub description: Option<String>,
    pub metadata: Value,
    pub owner_group_id: Option<GroupId>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl ListGraphsQuery {
    pub fn pagination(&self) -> (u32, u32) {
        let page = self.page.unwrap_or(1).max(1);
        let limit = self.limit.unwrap_or(25).clamp(1, 200);
        (page, limit)
    }
}

impl CreateGraphPayload {
    pub fn normalize(self) -> Result<GraphDefinition> {
        normalize_graph_definition(
            self.kind,
            self.name,
            self.description,
            self.metadata,
            self.owner_group_id,
            self.nodes,
            self.edges,
        )
    }
}

impl UpdateGraphPayload {
    pub fn normalize(self) -> Result<GraphDefinition> {
        normalize_graph_definition(
            self.kind,
            self.name,
            self.description,
            self.metadata,
            self.owner_group_id,
            self.nodes,
            self.edges,
        )
    }
}

impl ValidateGraphEdgesPayload {
    pub fn normalize(self) -> Result<GraphInvariantInput> {
        let nodes = normalize_nodes(self.nodes, false)?;
        let edges = normalize_validation_edges(self.edges);

        Ok(GraphInvariantInput {
            kind: self.kind,
            nodes,
            edges,
        })
    }
}

fn normalize_graph_definition(
    kind: GraphKind,
    name: String,
    description: Option<String>,
    metadata: Option<Value>,
    owner_group_id: Option<GroupId>,
    nodes: Vec<NewGraphNode>,
    edges: Vec<NewGraphEdge>,
) -> Result<GraphDefinition> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(LibError::invalid(
            "Graph name is required",
            anyhow!("empty graph name"),
        ));
    }

    let output_nodes = normalize_nodes(nodes, true)?;
    let output_edges = normalize_write_edges(edges, &output_nodes)?;
    invariants::ensure_graph_invariants(kind, &output_nodes, &output_edges)?;

    Ok(GraphDefinition {
        kind,
        name,
        description,
        metadata: metadata.unwrap_or_else(|| json!({})),
        owner_group_id,
        nodes: output_nodes,
        edges: output_edges,
    })
}

fn normalize_nodes(nodes: Vec<NewGraphNode>, require_non_empty: bool) -> Result<Vec<GraphNode>> {
    if require_non_empty && nodes.is_empty() {
        return Err(LibError::invalid(
            "At least one node is required",
            anyhow!("graph has no nodes"),
        ));
    }

    let mut seen_nodes = HashSet::with_capacity(nodes.len());
    let mut output_nodes = Vec::with_capacity(nodes.len());
    for node in nodes {
        let node_id = node.id.unwrap_or_else(|| GraphNodeId(Uuid::new_v4()));
        let label = node.label.trim().to_string();
        if label.is_empty() {
            return Err(LibError::invalid(
                "Node label is required",
                anyhow!("node {} had empty label", node_id),
            ));
        }

        if !seen_nodes.insert(node_id) {
            return Err(LibError::invalid(
                "Node IDs must be unique within a graph",
                anyhow!("duplicate node id {}", node_id),
            ));
        }

        output_nodes.push(GraphNode {
            id: node_id,
            label,
            metadata: node.metadata.unwrap_or_else(|| json!({})),
        });
    }

    Ok(output_nodes)
}

fn normalize_write_edges(edges: Vec<NewGraphEdge>, nodes: &[GraphNode]) -> Result<Vec<GraphEdge>> {
    let node_ids: HashSet<GraphNodeId> = nodes.iter().map(|node| node.id).collect();
    let mut seen_edges = HashSet::with_capacity(edges.len());
    let mut output_edges = Vec::with_capacity(edges.len());

    for edge in edges {
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

        output_edges.push(GraphEdge {
            from_node_id: edge.from_node_id,
            to_node_id: edge.to_node_id,
            metadata: edge.metadata.unwrap_or_else(|| json!({})),
        });
    }

    Ok(output_edges)
}

fn normalize_validation_edges(edges: Vec<NewGraphEdge>) -> Vec<GraphEdge> {
    edges
        .into_iter()
        .map(|edge| GraphEdge {
            from_node_id: edge.from_node_id,
            to_node_id: edge.to_node_id,
            metadata: edge.metadata.unwrap_or_else(|| json!({})),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CreateGraphPayload, GraphInvariantViolation, GraphKind, GraphNodeId, NewGraphEdge,
        NewGraphNode, UpdateGraphPayload, ValidateGraphEdgesPayload,
    };

    #[test]
    fn normalize_graph_generates_node_ids() {
        let payload = CreateGraphPayload {
            kind: GraphKind::Directed,
            name: "Roadmap".to_string(),
            description: None,
            metadata: None,
            owner_group_id: None,
            nodes: vec![
                NewGraphNode {
                    id: None,
                    label: "start".to_string(),
                    metadata: None,
                },
                NewGraphNode {
                    id: None,
                    label: "finish".to_string(),
                    metadata: None,
                },
            ],
            edges: vec![],
        };

        let normalized = payload.normalize().expect("payload should normalize");
        assert_eq!(normalized.nodes.len(), 2);
        assert_ne!(normalized.nodes[0].id, normalized.nodes[1].id);
    }

    #[test]
    fn normalize_graph_rejects_unknown_edge_nodes() {
        let node_id = GraphNodeId(uuid::Uuid::new_v4());
        let missing = GraphNodeId(uuid::Uuid::new_v4());
        let payload = CreateGraphPayload {
            kind: GraphKind::Directed,
            name: "Roadmap".to_string(),
            description: None,
            metadata: None,
            owner_group_id: None,
            nodes: vec![NewGraphNode {
                id: Some(node_id),
                label: "start".to_string(),
                metadata: Some(json!({})),
            }],
            edges: vec![NewGraphEdge {
                from_node_id: node_id,
                to_node_id: missing,
                metadata: None,
            }],
        };

        let err = payload.normalize().expect_err("should reject missing node");
        assert_eq!(err.public, "Edge destination node not found");
    }

    #[test]
    fn normalize_tree_rejects_cycles() {
        let node_a = GraphNodeId(uuid::Uuid::new_v4());
        let node_b = GraphNodeId(uuid::Uuid::new_v4());

        let payload = UpdateGraphPayload {
            kind: GraphKind::Tree,
            name: "Tree".to_string(),
            description: None,
            metadata: None,
            owner_group_id: None,
            nodes: vec![
                NewGraphNode {
                    id: Some(node_a),
                    label: "A".to_string(),
                    metadata: None,
                },
                NewGraphNode {
                    id: Some(node_b),
                    label: "B".to_string(),
                    metadata: None,
                },
            ],
            edges: vec![
                NewGraphEdge {
                    from_node_id: node_a,
                    to_node_id: node_b,
                    metadata: None,
                },
                NewGraphEdge {
                    from_node_id: node_b,
                    to_node_id: node_a,
                    metadata: None,
                },
            ],
        };

        let err = payload.normalize().expect_err("tree cycle should fail");
        assert_eq!(err.code, "graph_tree_cycle");
    }

    #[test]
    fn normalize_directed_allows_cycle() {
        let node_a = GraphNodeId(uuid::Uuid::new_v4());
        let node_b = GraphNodeId(uuid::Uuid::new_v4());

        let payload = UpdateGraphPayload {
            kind: GraphKind::Directed,
            name: "Directed".to_string(),
            description: None,
            metadata: None,
            owner_group_id: None,
            nodes: vec![
                NewGraphNode {
                    id: Some(node_a),
                    label: "A".to_string(),
                    metadata: None,
                },
                NewGraphNode {
                    id: Some(node_b),
                    label: "B".to_string(),
                    metadata: None,
                },
            ],
            edges: vec![
                NewGraphEdge {
                    from_node_id: node_a,
                    to_node_id: node_b,
                    metadata: None,
                },
                NewGraphEdge {
                    from_node_id: node_b,
                    to_node_id: node_a,
                    metadata: None,
                },
            ],
        };

        let normalized = payload
            .normalize()
            .expect("directed cycle should be allowed");
        assert_eq!(normalized.edges.len(), 2);
    }

    #[test]
    fn normalize_dag_rejects_self_loop() {
        let node = GraphNodeId(uuid::Uuid::new_v4());
        let payload = UpdateGraphPayload {
            kind: GraphKind::Dag,
            name: "Dag".to_string(),
            description: None,
            metadata: None,
            owner_group_id: None,
            nodes: vec![NewGraphNode {
                id: Some(node),
                label: "A".to_string(),
                metadata: None,
            }],
            edges: vec![NewGraphEdge {
                from_node_id: node,
                to_node_id: node,
                metadata: None,
            }],
        };

        let err = payload.normalize().expect_err("self-loop should fail");
        assert_eq!(err.code, "graph_self_loop_violation");
    }

    #[test]
    fn validate_payload_keeps_unknown_references_for_violation_reporting() {
        let node_a = GraphNodeId(uuid::Uuid::new_v4());
        let missing = GraphNodeId(uuid::Uuid::new_v4());
        let payload = ValidateGraphEdgesPayload {
            kind: GraphKind::Directed,
            nodes: vec![NewGraphNode {
                id: Some(node_a),
                label: "A".to_string(),
                metadata: None,
            }],
            edges: vec![NewGraphEdge {
                from_node_id: node_a,
                to_node_id: missing,
                metadata: None,
            }],
        };

        let normalized = payload
            .normalize()
            .expect("validation payload should normalize");
        let violations = crate::invariants::graph_invariant_violations(
            normalized.kind,
            &normalized.nodes,
            &normalized.edges,
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            GraphInvariantViolation::UnknownNodeReference {
                from_node_id,
                to_node_id,
                missing_node_id
            } if *from_node_id == node_a && *to_node_id == missing && *missing_node_id == missing
        ));
    }
}
