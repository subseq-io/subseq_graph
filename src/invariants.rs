use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::anyhow;

use crate::error::{LibError, Result};
use crate::models::{GraphEdge, GraphInvariantViolation, GraphKind, GraphNode, GraphNodeId};

#[derive(Debug, Clone)]
pub struct GraphMutationIndex {
    kind: GraphKind,
    node_ids: HashSet<GraphNodeId>,
    adjacency: HashMap<GraphNodeId, Vec<GraphNodeId>>,
    indegree: HashMap<GraphNodeId, usize>,
    roots: HashSet<GraphNodeId>,
    edge_set: HashSet<(GraphNodeId, GraphNodeId)>,
}

impl GraphMutationIndex {
    pub fn new(kind: GraphKind, nodes: &[GraphNode], edges: &[GraphEdge]) -> Self {
        let node_ids: HashSet<GraphNodeId> = nodes.iter().map(|node| node.id).collect();
        let mut adjacency: HashMap<GraphNodeId, Vec<GraphNodeId>> =
            HashMap::with_capacity(nodes.len());
        let mut indegree: HashMap<GraphNodeId, usize> = HashMap::with_capacity(nodes.len());
        for node in nodes {
            adjacency.insert(node.id, Vec::new());
            indegree.insert(node.id, 0);
        }

        let mut edge_set = HashSet::with_capacity(edges.len());
        for edge in edges {
            if !node_ids.contains(&edge.from_node_id) || !node_ids.contains(&edge.to_node_id) {
                continue;
            }
            if edge_set.insert((edge.from_node_id, edge.to_node_id)) {
                adjacency
                    .get_mut(&edge.from_node_id)
                    .expect("node should exist")
                    .push(edge.to_node_id);
                *indegree
                    .get_mut(&edge.to_node_id)
                    .expect("node should exist") += 1;
            }
        }

        let roots = indegree
            .iter()
            .filter_map(|(node_id, degree)| if *degree == 0 { Some(*node_id) } else { None })
            .collect::<HashSet<_>>();

        Self {
            kind,
            node_ids,
            adjacency,
            indegree,
            roots,
            edge_set,
        }
    }

    pub fn would_add_edge_violations(
        &self,
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
    ) -> Vec<GraphInvariantViolation> {
        let mut violations = Vec::new();
        if !self.node_ids.contains(&from_node_id) {
            violations.push(GraphInvariantViolation::UnknownNodeReference {
                from_node_id,
                to_node_id,
                missing_node_id: from_node_id,
            });
        }
        if !self.node_ids.contains(&to_node_id) {
            violations.push(GraphInvariantViolation::UnknownNodeReference {
                from_node_id,
                to_node_id,
                missing_node_id: to_node_id,
            });
        }
        if !violations.is_empty() || self.edge_set.contains(&(from_node_id, to_node_id)) {
            return violations;
        }

        if matches!(self.kind, GraphKind::Tree | GraphKind::Dag) && from_node_id == to_node_id {
            violations.push(GraphInvariantViolation::SelfLoop {
                node_id: from_node_id,
            });
        }

        if self.kind == GraphKind::Tree {
            let next_indegree = self
                .indegree
                .get(&to_node_id)
                .copied()
                .expect("to node should exist")
                + 1;
            if next_indegree > 1 {
                violations.push(GraphInvariantViolation::InDegreeExceeded {
                    node_id: to_node_id,
                    in_degree: next_indegree,
                });
            }
        }

        if matches!(self.kind, GraphKind::Tree | GraphKind::Dag)
            && self.path_exists(
                to_node_id,
                from_node_id,
                Some((from_node_id, to_node_id)),
                None,
            )
        {
            violations.push(GraphInvariantViolation::CycleDetected);
        }

        if self.kind == GraphKind::Tree {
            let mut roots_after = self.roots.clone();
            if self.indegree.get(&to_node_id).copied().unwrap_or(0) == 0 {
                roots_after.remove(&to_node_id);
            }

            if roots_after.len() != 1 {
                violations.push(GraphInvariantViolation::InvalidRootCount {
                    root_count: roots_after.len(),
                });
                return violations;
            }

            let root = roots_after
                .iter()
                .next()
                .copied()
                .expect("single-root set should have one root");
            let reachable = self.reachable_nodes(root, Some((from_node_id, to_node_id)), None);
            if reachable.len() != self.node_ids.len() {
                let mut unreachable = self
                    .node_ids
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

        violations
    }

    pub fn would_remove_edge_violations(
        &self,
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
    ) -> Vec<GraphInvariantViolation> {
        if !self.edge_set.contains(&(from_node_id, to_node_id)) {
            return Vec::new();
        }

        let mut violations = Vec::new();
        if self.kind != GraphKind::Tree {
            return violations;
        }

        let mut roots_after = self.roots.clone();
        let current_indegree = self.indegree.get(&to_node_id).copied().unwrap_or(0);
        if current_indegree == 1 {
            roots_after.insert(to_node_id);
        }

        if roots_after.len() != 1 {
            violations.push(GraphInvariantViolation::InvalidRootCount {
                root_count: roots_after.len(),
            });
        } else {
            let root = roots_after
                .iter()
                .next()
                .copied()
                .expect("single-root set should have one root");
            let reachable = self.reachable_nodes(root, None, Some((from_node_id, to_node_id)));
            if reachable.len() != self.node_ids.len() {
                let mut unreachable = self
                    .node_ids
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

        violations
    }

    pub fn would_remove_edge_isolate_subgraph(
        &self,
        from_node_id: GraphNodeId,
        to_node_id: GraphNodeId,
    ) -> bool {
        if !self.edge_set.contains(&(from_node_id, to_node_id)) {
            return false;
        }
        if self.node_ids.len() <= 1 {
            return false;
        }

        let root = if let Some(root) = self.roots.iter().next().copied() {
            root
        } else {
            return false;
        };
        let reachable = self.reachable_nodes(root, None, Some((from_node_id, to_node_id)));
        reachable.len() != self.node_ids.len()
    }

    fn path_exists(
        &self,
        start: GraphNodeId,
        target: GraphNodeId,
        virtual_add: Option<(GraphNodeId, GraphNodeId)>,
        virtual_remove: Option<(GraphNodeId, GraphNodeId)>,
    ) -> bool {
        if start == target {
            return true;
        }
        if !self.node_ids.contains(&start) || !self.node_ids.contains(&target) {
            return false;
        }

        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(start);
        queue.push_back(start);

        while let Some(node_id) = queue.pop_front() {
            let mut neighbors = self.adjacency.get(&node_id).cloned().unwrap_or_default();
            if let Some((from, to)) = virtual_add {
                if from == node_id && !neighbors.contains(&to) {
                    neighbors.push(to);
                }
            }

            for next in neighbors {
                if let Some((remove_from, remove_to)) = virtual_remove {
                    if remove_from == node_id && remove_to == next {
                        continue;
                    }
                }
                if next == target {
                    return true;
                }
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }

        false
    }

    fn reachable_nodes(
        &self,
        root: GraphNodeId,
        virtual_add: Option<(GraphNodeId, GraphNodeId)>,
        virtual_remove: Option<(GraphNodeId, GraphNodeId)>,
    ) -> HashSet<GraphNodeId> {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(root);
        queue.push_back(root);

        while let Some(node_id) = queue.pop_front() {
            let mut neighbors = self.adjacency.get(&node_id).cloned().unwrap_or_default();
            if let Some((from, to)) = virtual_add {
                if from == node_id && !neighbors.contains(&to) {
                    neighbors.push(to);
                }
            }

            for next in neighbors {
                if let Some((remove_from, remove_to)) = virtual_remove {
                    if remove_from == node_id && remove_to == next {
                        continue;
                    }
                }
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }

        seen
    }
}

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

    #[test]
    fn add_edge_delta_check_reports_cycle_for_dag() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let c = GraphNodeId(Uuid::new_v4());
        let nodes = vec![node(a, "A"), node(b, "B"), node(c, "C")];
        let edges = vec![edge(a, b), edge(b, c)];
        let index = GraphMutationIndex::new(GraphKind::Dag, &nodes, &edges);

        let violations = index.would_add_edge_violations(c, a);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, GraphInvariantViolation::CycleDetected))
        );
    }

    #[test]
    fn add_edge_delta_check_allows_cycle_for_directed() {
        let a = GraphNodeId(Uuid::new_v4());
        let b = GraphNodeId(Uuid::new_v4());
        let nodes = vec![node(a, "A"), node(b, "B")];
        let edges = vec![edge(a, b)];
        let index = GraphMutationIndex::new(GraphKind::Directed, &nodes, &edges);

        let violations = index.would_add_edge_violations(b, a);
        assert!(violations.is_empty());
    }

    #[test]
    fn remove_edge_delta_check_reports_tree_isolation() {
        let root = GraphNodeId(Uuid::new_v4());
        let child = GraphNodeId(Uuid::new_v4());
        let leaf = GraphNodeId(Uuid::new_v4());
        let nodes = vec![node(root, "root"), node(child, "child"), node(leaf, "leaf")];
        let edges = vec![edge(root, child), edge(child, leaf)];
        let index = GraphMutationIndex::new(GraphKind::Tree, &nodes, &edges);

        let violations = index.would_remove_edge_violations(root, child);
        assert!(violations.iter().any(|v| matches!(
            v,
            GraphInvariantViolation::InvalidRootCount { .. }
        ) || matches!(
            v,
            GraphInvariantViolation::DisconnectedTree { .. }
        )));
        assert!(index.would_remove_edge_isolate_subgraph(root, child));
    }
}
