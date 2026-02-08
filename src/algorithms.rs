use std::collections::{HashMap, VecDeque};

use crate::models::{DirectedGraph, GraphNode, GraphNodeId};

pub fn adjacency_map(graph: &DirectedGraph) -> HashMap<GraphNodeId, Vec<GraphNodeId>> {
    let mut adjacency = HashMap::new();
    let mut known_nodes = HashMap::new();
    for node in &graph.nodes {
        adjacency.entry(node.id).or_insert_with(Vec::new);
        known_nodes.insert(node.id, ());
    }
    for edge in &graph.edges {
        if !known_nodes.contains_key(&edge.from_node_id)
            || !known_nodes.contains_key(&edge.to_node_id)
        {
            // Best-effort behavior: skip dangling edges instead of failing the whole computation.
            continue;
        }
        adjacency
            .entry(edge.from_node_id)
            .or_insert_with(Vec::new)
            .push(edge.to_node_id);
    }
    adjacency
}

pub fn has_cycle(graph: &DirectedGraph) -> bool {
    topological_sort(graph).len() != graph.nodes.len()
}

pub fn topological_sort(graph: &DirectedGraph) -> Vec<&GraphNode> {
    let mut node_lookup = HashMap::with_capacity(graph.nodes.len());
    let mut indegree: HashMap<GraphNodeId, usize> = HashMap::with_capacity(graph.nodes.len());
    let mut adjacency: HashMap<GraphNodeId, Vec<GraphNodeId>> =
        HashMap::with_capacity(graph.nodes.len());

    for node in &graph.nodes {
        node_lookup.insert(node.id, node);
        indegree.insert(node.id, 0);
        adjacency.insert(node.id, Vec::new());
    }

    for edge in &graph.edges {
        // Best-effort behavior: ignore invalid edge endpoints.
        if !node_lookup.contains_key(&edge.from_node_id)
            || !node_lookup.contains_key(&edge.to_node_id)
        {
            continue;
        }
        *indegree
            .get_mut(&edge.to_node_id)
            .expect("to_node_id should exist in indegree") += 1;
        adjacency
            .entry(edge.from_node_id)
            .or_insert_with(Vec::new)
            .push(edge.to_node_id);
    }

    let mut queue = VecDeque::new();
    for (node_id, degree) in &indegree {
        if *degree == 0 {
            queue.push_back(*node_id);
        }
    }

    let mut ordered = Vec::with_capacity(graph.nodes.len());
    while let Some(node_id) = queue.pop_front() {
        if let Some(node) = node_lookup.get(&node_id) {
            ordered.push(*node);
        }
        if let Some(children) = adjacency.get(&node_id) {
            for child in children {
                if let Some(child_degree) = indegree.get_mut(child) {
                    *child_degree -= 1;
                    if *child_degree == 0 {
                        queue.push_back(*child);
                    }
                }
            }
        }
    }

    ordered
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;
    use subseq_auth::user_id::UserId;

    use crate::models::{DirectedGraph, GraphEdge, GraphId, GraphNode, GraphNodeId};

    fn sample_graph() -> DirectedGraph {
        let n1 = GraphNode {
            id: GraphNodeId(uuid::Uuid::new_v4()),
            label: "A".to_string(),
            metadata: json!({}),
        };
        let n2 = GraphNode {
            id: GraphNodeId(uuid::Uuid::new_v4()),
            label: "B".to_string(),
            metadata: json!({}),
        };

        DirectedGraph {
            id: GraphId(uuid::Uuid::new_v4()),
            owner_user_id: UserId(uuid::Uuid::new_v4()),
            owner_group_id: None,
            name: "Example".to_string(),
            description: None,
            metadata: json!({}),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
            nodes: vec![n1.clone(), n2.clone()],
            edges: vec![GraphEdge {
                from_node_id: n1.id,
                to_node_id: n2.id,
                metadata: json!({}),
            }],
        }
    }

    #[test]
    fn dag_has_no_cycle() {
        let graph = sample_graph();
        assert!(!super::has_cycle(&graph));
        assert_eq!(super::topological_sort(&graph).len(), 2);
    }

    #[test]
    fn cycle_detects_properly() {
        let mut graph = sample_graph();
        graph.edges.push(GraphEdge {
            from_node_id: graph.nodes[1].id,
            to_node_id: graph.nodes[0].id,
            metadata: json!({}),
        });
        assert!(super::has_cycle(&graph));
    }
}
