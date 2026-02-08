use std::collections::HashSet;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;
use uuid::Uuid;

use subseq_graph::invariants::GraphMutationIndex;
use subseq_graph::models::{GraphEdge, GraphKind, GraphNode, GraphNodeId};

fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

fn node(id: GraphNodeId) -> GraphNode {
    GraphNode {
        id,
        label: "N".to_string(),
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

fn synthetic_dag(node_count: usize, edge_count: usize) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let nodes = (0..node_count)
        .map(|idx| {
            let id = GraphNodeId(Uuid::from_u128((idx as u128) + 1));
            node(id)
        })
        .collect::<Vec<_>>();
    let ids = nodes.iter().map(|n| n.id).collect::<Vec<_>>();

    let mut state = 0x1234_5678_9abc_def0u64;
    let mut seen = HashSet::with_capacity(edge_count);
    let mut edges = Vec::with_capacity(edge_count);
    while edges.len() < edge_count {
        let a = (lcg_next(&mut state) as usize) % node_count;
        let b = (lcg_next(&mut state) as usize) % node_count;
        if a == b {
            continue;
        }
        let (from, to) = if a < b { (a, b) } else { (b, a) };
        let pair = (ids[from], ids[to]);
        if seen.insert(pair) {
            edges.push(edge(pair.0, pair.1));
        }
    }

    (nodes, edges)
}

fn bench_add_edge_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_edge_checks");
    for (nodes, edges) in [(1_000usize, 3_000usize), (3_000usize, 9_000usize)] {
        let (node_data, edge_data) = synthetic_dag(nodes, edges);
        let index = GraphMutationIndex::new(GraphKind::Dag, &node_data, &edge_data);
        let ids = node_data.iter().map(|n| n.id).collect::<Vec<_>>();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("dag_add_edge", format!("{nodes}n_{edges}e")),
            &(index, ids),
            |b, (index, ids)| {
                let mut seed = 42u64;
                b.iter(|| {
                    let from = ids[(lcg_next(&mut seed) as usize) % ids.len()];
                    let to = ids[(lcg_next(&mut seed) as usize) % ids.len()];
                    black_box(index.would_add_edge_violations(from, to));
                });
            },
        );
    }
    group.finish();
}

fn bench_remove_edge_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove_edge_checks");
    for (nodes, edges) in [(1_000usize, 3_000usize), (3_000usize, 9_000usize)] {
        let (node_data, edge_data) = synthetic_dag(nodes, edges);
        let index = GraphMutationIndex::new(GraphKind::Tree, &node_data, &edge_data[..nodes - 1]);
        let remove_targets = edge_data[..nodes - 1].to_vec();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("tree_remove_edge", format!("{nodes}n_{}e", nodes - 1)),
            &(index, remove_targets),
            |b, (index, remove_targets)| {
                let mut idx = 0usize;
                b.iter(|| {
                    let edge = &remove_targets[idx % remove_targets.len()];
                    idx = idx.wrapping_add(1);
                    black_box(
                        index.would_remove_edge_violations(edge.from_node_id, edge.to_node_id),
                    );
                    black_box(
                        index
                            .would_remove_edge_isolate_subgraph(edge.from_node_id, edge.to_node_id),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    mutation_checks,
    bench_add_edge_checks,
    bench_remove_edge_checks
);
criterion_main!(mutation_checks);
