use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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

#[derive(Debug, Clone, PartialEq)]
pub struct ApiMetadata(pub Map<String, Value>);

#[derive(Debug, Clone, PartialEq)]
pub struct DbMetadata(pub Map<String, Value>);

#[derive(Debug, Clone, Copy)]
enum MetadataKeyCase {
    Camel,
    Snake,
}

impl TryFrom<Value> for ApiMetadata {
    type Error = LibError;

    fn try_from(value: Value) -> Result<Self> {
        let normalized = canonicalize_metadata_value(value, MetadataKeyCase::Camel, "$")?;
        match normalized {
            Value::Object(map) => Ok(Self(map)),
            _ => Err(LibError::invalid(
                "Metadata must be a JSON object",
                anyhow!("metadata payload was not an object after normalization"),
            )),
        }
    }
}

impl TryFrom<Value> for DbMetadata {
    type Error = LibError;

    fn try_from(value: Value) -> Result<Self> {
        let normalized = canonicalize_metadata_value(value, MetadataKeyCase::Snake, "$")?;
        match normalized {
            Value::Object(map) => Ok(Self(map)),
            _ => Err(LibError::invalid(
                "Metadata must be a JSON object",
                anyhow!("database metadata payload was not an object after normalization"),
            )),
        }
    }
}

impl From<ApiMetadata> for DbMetadata {
    fn from(value: ApiMetadata) -> Self {
        let input = Value::Object(value.0);
        let normalized = canonicalize_metadata_value(input, MetadataKeyCase::Snake, "$")
            .expect("canonical api metadata should always convert to db metadata");
        let Value::Object(map) = normalized else {
            unreachable!("metadata normalization output must be an object");
        };
        Self(map)
    }
}

impl From<DbMetadata> for ApiMetadata {
    fn from(value: DbMetadata) -> Self {
        let input = Value::Object(value.0);
        let normalized = canonicalize_metadata_value(input, MetadataKeyCase::Camel, "$")
            .expect("canonical db metadata should always convert to api metadata");
        let Value::Object(map) = normalized else {
            unreachable!("metadata normalization output must be an object");
        };
        Self(map)
    }
}

impl From<ApiMetadata> for Value {
    fn from(value: ApiMetadata) -> Self {
        Value::Object(value.0)
    }
}

impl From<DbMetadata> for Value {
    fn from(value: DbMetadata) -> Self {
        Value::Object(value.0)
    }
}

pub fn normalize_api_metadata(metadata: Option<Value>) -> Result<Value> {
    let input = metadata.unwrap_or_else(|| Value::Object(Map::new()));
    let api_metadata = ApiMetadata::try_from(input)?;
    Ok(Value::from(api_metadata))
}

pub fn api_metadata_to_db_json(metadata: &Value) -> Result<Value> {
    let api_metadata = ApiMetadata::try_from(metadata.clone())?;
    let db_metadata = DbMetadata::from(api_metadata);
    Ok(Value::from(db_metadata))
}

pub fn db_metadata_to_api_json(metadata: &Value) -> Result<Value> {
    let db_metadata = DbMetadata::try_from(metadata.clone())?;
    let api_metadata = ApiMetadata::from(db_metadata);
    Ok(Value::from(api_metadata))
}

fn canonicalize_metadata_value(value: Value, case: MetadataKeyCase, path: &str) -> Result<Value> {
    match value {
        Value::Object(map) => {
            let mut normalized = Map::with_capacity(map.len());
            for (raw_key, raw_value) in map {
                let key = canonicalize_metadata_key(&raw_key, case);
                if key.is_empty() {
                    return Err(LibError::invalid(
                        "Metadata keys must be non-empty",
                        anyhow!("empty metadata key encountered at {}", path),
                    ));
                }

                let child_path = format!("{}.{}", path, key);
                let value = canonicalize_metadata_value(raw_value, case, &child_path)?;
                if normalized.insert(key.clone(), value).is_some() {
                    return Err(LibError::invalid(
                        "Metadata contains conflicting keys after normalization",
                        anyhow!(
                            "metadata key collision for '{}' while normalizing {} at {}",
                            key,
                            case.as_str(),
                            path
                        ),
                    ));
                }
            }

            Ok(Value::Object(normalized))
        }
        Value::Array(values) => {
            let mut normalized = Vec::with_capacity(values.len());
            for (idx, value) in values.into_iter().enumerate() {
                let child_path = format!("{}[{}]", path, idx);
                normalized.push(canonicalize_metadata_value(value, case, &child_path)?);
            }
            Ok(Value::Array(normalized))
        }
        _ => Ok(value),
    }
}

impl MetadataKeyCase {
    const fn as_str(self) -> &'static str {
        match self {
            MetadataKeyCase::Camel => "camelCase",
            MetadataKeyCase::Snake => "snake_case",
        }
    }
}

fn canonicalize_metadata_key(key: &str, case: MetadataKeyCase) -> String {
    match case {
        MetadataKeyCase::Camel => to_camel_case_key(key),
        MetadataKeyCase::Snake => to_snake_case_key(key),
    }
}

fn to_camel_case_key(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut uppercase_next = false;

    for ch in input.chars() {
        if !ch.is_alphanumeric() {
            uppercase_next = !output.is_empty();
            continue;
        }

        if output.is_empty() {
            output.push(ch.to_ascii_lowercase());
            uppercase_next = false;
            continue;
        }

        if uppercase_next {
            output.push(ch.to_ascii_uppercase());
            uppercase_next = false;
        } else {
            output.push(ch);
        }
    }

    output
}

fn to_snake_case_key(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut output = String::with_capacity(input.len());
    let mut prev_was_separator = false;

    for (idx, ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            if !output.is_empty() && !prev_was_separator {
                output.push('_');
                prev_was_separator = true;
            }
            continue;
        }

        let is_upper = ch.is_ascii_uppercase();
        if is_upper && !output.is_empty() && !prev_was_separator {
            let prev = chars[idx.saturating_sub(1)];
            let prev_is_lower_or_digit = prev.is_ascii_lowercase() || prev.is_ascii_digit();
            let prev_is_upper = prev.is_ascii_uppercase();
            let next_is_lower = chars
                .get(idx + 1)
                .is_some_and(|next| next.is_ascii_lowercase());
            if prev_is_lower_or_digit || (prev_is_upper && next_is_lower) {
                output.push('_');
            }
        }

        output.push(ch.to_ascii_lowercase());
        prev_was_separator = false;
    }

    output.trim_matches('_').to_string()
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertNodePayload {
    pub node_id: Option<GraphNodeId>,
    pub label: String,
    pub metadata: Option<Value>,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveNodePayload {
    pub node_id: GraphNodeId,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReparentNodePayload {
    pub node_id: GraphNodeId,
    #[serde(default)]
    pub new_parent_node_id: Option<GraphNodeId>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddEdgePayload {
    pub from_node_id: GraphNodeId,
    pub to_node_id: GraphNodeId,
    pub metadata: Option<Value>,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveEdgePayload {
    pub from_node_id: GraphNodeId,
    pub to_node_id: GraphNodeId,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertEdgeMetadataPayload {
    pub from_node_id: GraphNodeId,
    pub to_node_id: GraphNodeId,
    pub metadata: Value,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataFilterPayload {
    pub metadata_contains: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardedUpdateGraphPayload {
    pub graph: UpdateGraphPayload,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum GraphDeltaOperation {
    AddEdge {
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
        metadata: Option<Value>,
    },
    RemoveEdge {
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
    },
    UpsertEdgeMetadata {
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
        metadata: Value,
    },
    UpsertNode {
        node_id: Option<GraphNodeId>,
        label: String,
        metadata: Option<Value>,
    },
    ReparentNode {
        node_id: GraphNodeId,
        new_parent_node_id: Option<GraphNodeId>,
        metadata: Option<Value>,
    },
    RemoveNode {
        node_id: GraphNodeId,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphDeltaCommand {
    pub graph_id: GraphId,
    #[serde(flatten)]
    pub operation: GraphDeltaOperation,
    #[serde(default)]
    pub expected_updated_at: Option<NaiveDateTime>,
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
        let edges = normalize_validation_edges(self.edges)?;

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
        metadata: normalize_api_metadata(metadata)?,
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
            metadata: normalize_api_metadata(node.metadata)?,
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
            metadata: normalize_api_metadata(edge.metadata)?,
        });
    }

    Ok(output_edges)
}

fn normalize_validation_edges(edges: Vec<NewGraphEdge>) -> Result<Vec<GraphEdge>> {
    edges
        .into_iter()
        .map(|edge| -> Result<GraphEdge> {
            let metadata = normalize_api_metadata(edge.metadata)?;
            Ok(GraphEdge {
                from_node_id: edge.from_node_id,
                to_node_id: edge.to_node_id,
                metadata,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CreateGraphPayload, GraphInvariantViolation, GraphKind, GraphNodeId, NewGraphEdge,
        NewGraphNode, UpdateGraphPayload, ValidateGraphEdgesPayload, api_metadata_to_db_json,
        db_metadata_to_api_json, normalize_api_metadata,
    };

    #[test]
    fn normalize_api_metadata_converts_nested_keys_to_camel_case() {
        let metadata = normalize_api_metadata(Some(json!({
            "external_id": "task-1",
            "nested_value": {"created_at": "2026-02-08"},
            "items": [
                {"task_id": "a"},
                {"task_id": "b"}
            ]
        })))
        .expect("metadata should normalize");

        assert_eq!(
            metadata,
            json!({
                "externalId": "task-1",
                "nestedValue": {"createdAt": "2026-02-08"},
                "items": [
                    {"taskId": "a"},
                    {"taskId": "b"}
                ]
            })
        );
    }

    #[test]
    fn api_metadata_db_conversion_round_trips_case() {
        let api_metadata = json!({
            "externalId": "task-1",
            "nestedValue": {"createdAt": "2026-02-08"}
        });

        let db_metadata = api_metadata_to_db_json(&api_metadata).expect("api->db conversion");
        assert_eq!(
            db_metadata,
            json!({
                "external_id": "task-1",
                "nested_value": {"created_at": "2026-02-08"}
            })
        );

        let round_trip = db_metadata_to_api_json(&db_metadata).expect("db->api conversion");
        assert_eq!(round_trip, api_metadata);
    }

    #[test]
    fn normalize_api_metadata_rejects_non_object_payloads() {
        let err = normalize_api_metadata(Some(json!("not-an-object")))
            .expect_err("scalar metadata should be rejected");

        assert_eq!(err.code, "invalid_input");
        assert_eq!(err.public, "Metadata must be a JSON object");
    }

    #[test]
    fn normalize_api_metadata_rejects_casing_collisions() {
        let err = normalize_api_metadata(Some(json!({
            "external_id": "a",
            "externalId": "b"
        })))
        .expect_err("colliding keys should be rejected");

        assert_eq!(err.code, "invalid_input");
        assert_eq!(
            err.public,
            "Metadata contains conflicting keys after normalization"
        );
    }

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
