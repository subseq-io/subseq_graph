use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::anyhow;

use crate::error::{LibError, Result};
use crate::models::{GraphEdge, GraphInvariantViolation, GraphKind, GraphNode, GraphNodeId};

pub fn graph_invariant_violations(
    kind: GraphKind,
    nodes: &[GraphNode],
    edges: &[GraphEdge],
) -> Vec<GraphInvariantViolation> {
    let node_ids: HashSet<GraphNodeId> = nodes.iter().map(|node| node.id).collect();
    let mut indegree: HashMap<GraphNodeId, usize> = HashMap::with_capacity(nodes.len());
    let mut adjacency: HashMap<GraphNodeId, Vec<GraphNodeId>> = HashMap::with_capacity(nodes.len());
    for node in nodes {
        indegree.insert(node.id, 0);
        adjacency.insert(node.id, Vec::new());
    }

    let mut violations = Vec::new();
    for edge in edges {
        if !node_ids.contains(&edge.from_node_id) {
            violations.push(GraphInvariantViolation::UnknownNodeReference {
                from_node_id: edge.from_node_id,
                to_node_id: edge.to_node_id,
                missing_node_id: edge.from_node_id,
            });
            continue;
        }
        if !node_ids.contains(&edge.to_node_id) {
            violations.push(GraphInvariantViolation::UnknownNodeReference {
                from_node_id: edge.from_node_id,
                to_node_id: edge.to_node_id,
                missing_node_id: edge.to_node_id,
            });
            continue;
        }

        if edge.from_node_id == edge.to_node_id && matches!(kind, GraphKind::Tree | GraphKind::Dag)
        {
            violations.push(GraphInvariantViolation::SelfLoop {
                node_id: edge.from_node_id,
            });
        }

        *indegree
            .get_mut(&edge.to_node_id)
            .expect("to_node_id should exist in indegree map") += 1;
        adjacency
            .get_mut(&edge.from_node_id)
            .expect("from_node_id should exist in adjacency map")
            .push(edge.to_node_id);
    }

    match kind {
        GraphKind::Directed => {}
        GraphKind::Dag => {
            if has_cycle(nodes, &adjacency, &indegree) {
                violations.push(GraphInvariantViolation::CycleDetected);
            }
        }
        GraphKind::Tree => {
            for (node_id, degree) in &indegree {
                if *degree > 1 {
                    violations.push(GraphInvariantViolation::InDegreeExceeded {
                        node_id: *node_id,
                        in_degree: *degree,
                    });
                }
            }

            if has_cycle(nodes, &adjacency, &indegree) {
                violations.push(GraphInvariantViolation::CycleDetected);
            }

            let roots: Vec<GraphNodeId> = indegree
                .iter()
                .filter_map(|(node_id, degree)| if *degree == 0 { Some(*node_id) } else { None })
                .collect();

            if roots.len() != 1 {
                violations.push(GraphInvariantViolation::InvalidRootCount {
                    root_count: roots.len(),
                });
            } else {
                let root = roots[0];
                let reachable = reachable_nodes(root, &adjacency);
                if reachable.len() != node_ids.len() {
                    let mut unreachable = node_ids
                        .iter()
                        .filter(|node_id| !reachable.contains(node_id))
                        .copied()
                        .collect::<Vec<_>>();
                    unreachable.sort_by_key(|node_id| node_id.0);
                    violations.push(GraphInvariantViolation::DisconnectedTree {
                        unreachable_node_ids: unreachable,
                    });
                }
            }
        }
    }

    violations
}

pub fn ensure_graph_invariants(
    kind: GraphKind,
    nodes: &[GraphNode],
    edges: &[GraphEdge],
) -> Result<()> {
    let violations = graph_invariant_violations(kind, nodes, edges);
    if let Some(first) = violations.first() {
        return Err(LibError::invalid_with_code(
            first.error_code(kind),
            first.public_message(kind),
            anyhow!(
                "graph invariant validation failed for kind {}: {:?}",
                kind.as_db_value(),
                violations
            ),
        ));
    }

    Ok(())
}

fn has_cycle(
    nodes: &[GraphNode],
    adjacency: &HashMap<GraphNodeId, Vec<GraphNodeId>>,
    indegree: &HashMap<GraphNodeId, usize>,
) -> bool {
    let mut indegree = indegree.clone();
    let mut queue = VecDeque::new();
    for (node_id, degree) in &indegree {
        if *degree == 0 {
            queue.push_back(*node_id);
        }
    }

    let mut visited_count = 0usize;
    while let Some(node_id) = queue.pop_front() {
        visited_count += 1;
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

    visited_count != nodes.len()
}

fn reachable_nodes(
    root: GraphNodeId,
    adjacency: &HashMap<GraphNodeId, Vec<GraphNodeId>>,
) -> HashSet<GraphNodeId> {
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(root);
    reachable.insert(root);

    while let Some(node_id) = queue.pop_front() {
        if let Some(children) = adjacency.get(&node_id) {
            for child in children {
                if reachable.insert(*child) {
                    queue.push_back(*child);
                }
            }
        }
    }

    reachable
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn node(id: GraphNodeId, label: &str) -> GraphNode {
        GraphNode {
            id,
            label: label.to_string(),
            metadata: json!({}),
        }
    }

    fn edge(from: GraphNodeId, to: GraphNodeId) -> GraphEdge {
        GraphEdge {
            from_node_id: from,
            to_node_id: to,
            metadata: json!({}),
        }
    }

    #[test]
    fn directed_allows_cycles() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(
            GraphKind::Directed,
            &[node(a, "A"), node(b, "B")],
            &[edge(a, b), edge(b, a)],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn dag_rejects_cycles() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(
            GraphKind::Dag,
            &[node(a, "A"), node(b, "B")],
            &[edge(a, b), edge(b, a)],
        );
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::CycleDetected))
        );
    }

    #[test]
    fn dag_rejects_self_loop() {
        let a = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(GraphKind::Dag, &[node(a, "A")], &[edge(a, a)]);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::SelfLoop { .. }))
        );
    }

    #[test]
    fn dag_accepts_acyclic_graph() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(
            GraphKind::Dag,
            &[node(a, "A"), node(b, "B"), node(c, "C")],
            &[edge(a, b), edge(b, c)],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn tree_rejects_self_loop() {
        let a = GraphNodeId(Uuid::new_v4());
        let violations =
            graph_invariant_violations(GraphKind::Tree, &[node(a, "A")], &[edge(a, a)]);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::SelfLoop { .. }))
        );
    }

    #[test]
    fn tree_rejects_in_degree_above_one() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(
            GraphKind::Tree,
            &[node(a, "A"), node(b, "B"), node(c, "C")],
            &[edge(a, c), edge(b, c)],
        );
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::InDegreeExceeded { node_id, .. } if *node_id == c))
        );
    }

    #[test]
    fn tree_requires_single_root() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let violations =
            graph_invariant_violations(GraphKind::Tree, &[node(a, "A"), node(b, "B")], &[]);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::InvalidRootCount { root_count } if *root_count == 2))
        );
    }

    #[test]
    fn tree_requires_connected_rooted_structure() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let d = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(
            GraphKind::Tree,
            &[node(a, "A"), node(b, "B"), node(c, "C"), node(d, "D")],
            &[edge(a, b), edge(c, d), edge(d, c)],
        );
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::DisconnectedTree { unreachable_node_ids } if unreachable_node_ids.contains(&c) && unreachable_node_ids.contains(&d)))
        );
    }

    #[test]
    fn tree_accepts_valid_rooted_tree() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let violations = graph_invariant_violations(
            GraphKind::Tree,
            &[node(a, "A"), node(b, "B"), node(c, "C")],
            &[edge(a, b), edge(a, c)],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn unknown_node_references_are_reported() {
        let a = GraphNodeId(Uuid::new_v4());
        let missing = GraphNodeId(Uuid::new_v4());
        let violations =
            graph_invariant_violations(GraphKind::Directed, &[node(a, "A")], &[edge(a, missing)]);
        assert!(matches!(
            &violations[0],
            GraphInvariantViolation::UnknownNodeReference {
                from_node_id,
                to_node_id,
                missing_node_id
            } if *from_node_id == a && *to_node_id == missing && *missing_node_id == missing
        ));
    }
}
