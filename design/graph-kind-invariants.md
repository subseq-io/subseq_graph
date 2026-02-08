# Graph Kind and Invariant Requirements

## Scope

Add graph kinds and enforce kind-specific edge/structure invariants across write
paths, with a validation API for machine-readable violation reporting.

## Kinds

- `tree`
- `dag`
- `directed`

## Persistence

- Graph kind is persisted on `graph.graphs.kind`.
- Allowed values are constrained to `tree`, `dag`, `directed`.
- Existing rows default to `directed`.

## Invariants

### `tree`

- No self-loop edges.
- Acyclic.
- In-degree <= 1 for every node.
- Exactly one root node (in-degree 0).
- Rooted connectivity: all nodes reachable from the root.

### `dag`

- No self-loop edges.
- Acyclic.

### `directed`

- Cycles allowed.

## Enforcement Paths

- `create` graph writes.
- `update` graph writes.
- `extend` graph writes (via merged update payload).
- DB write path includes invariant re-check as defense in depth.

Invariant failures are validation errors (`invalid_input` class) with stable
machine-readable `error.code` values (for example `graph_tree_cycle`,
`graph_dag_cycle`, `graph_self_loop_violation`).

## Validation API

- `POST /graph/validate`
- Input: `{ kind, nodes, edges }`
- Output: `{ valid, violations[] }`
- Violations are machine-readable tagged variants (`type`) including:
  - `unknown_node_reference`
  - `self_loop`
  - `cycle_detected`
  - `in_degree_exceeded`
  - `invalid_root_count`
  - `disconnected_tree`

## Low-Cost Mutation Checks

For preflight checks on single-edge edits, use an in-memory mutation index:

- Precompute once per graph:
  - node set
  - edge set
  - adjacency
  - in-degree
  - root set
- Evaluate deltas without full write-path normalization:
  - `would_add_edge_violations(from, to)`
  - `would_remove_edge_violations(from, to)`
  - `would_remove_edge_isolate_subgraph(from, to)`

API surfaces:

- `POST /graph/{graph_id}/validate/add-edge`
- `POST /graph/{graph_id}/validate/remove-edge`

Response includes:

- `valid`
- `wouldIntroduceViolation`
- `wouldIsolateSubgraph`
- `violations[]`

## Performance Validation

Use Criterion benchmarks (not unit tests) on synthetic random graphs in the
thousands-scale range to guard against regressions in single-mutation checks:

- Benchmark target: `benches/mutation_checks.rs`
- Run with: `cargo bench --bench mutation_checks`
- Sizes currently covered:
  - `1,000` nodes / `3,000` edges
  - `3,000` nodes / `9,000` edges
- Measures per-operation latency/throughput for:
  - add-edge preflight checks
  - remove-edge preflight checks (including isolate-subgraph signal)

## Auth

- Existing auth model and scope checks remain unchanged.
- Invariant failures are validation errors, not authorization errors.
