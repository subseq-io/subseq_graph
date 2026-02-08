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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectedGraph {
    pub id: GraphId,
    pub owner_user_id: UserId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_group_id: Option<GroupId>,
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

#[derive(Debug, Clone)]
pub struct GraphDefinition {
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
            self.name,
            self.description,
            self.metadata,
            self.owner_group_id,
            self.nodes,
            self.edges,
        )
    }
}

fn normalize_graph_definition(
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

    if nodes.is_empty() {
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

    let node_ids: HashSet<GraphNodeId> = output_nodes.iter().map(|node| node.id).collect();
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

    Ok(GraphDefinition {
        name,
        description,
        metadata: metadata.unwrap_or_else(|| json!({})),
        owner_group_id,
        nodes: output_nodes,
        edges: output_edges,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CreateGraphPayload, GraphNodeId, NewGraphEdge, NewGraphNode};

    #[test]
    fn normalize_graph_generates_node_ids() {
        let payload = CreateGraphPayload {
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
}
