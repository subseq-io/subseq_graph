# Graph Ease-of-Use Delta Surface

## Problem

Task workflows need ergonomic graph mutation and lookup APIs that avoid
full-graph replacement for every change and support cross-graph atomic updates.

## Decisions

1. Add transactional delta mutation APIs:
   - `add_edge` / `remove_edge` / `upsert_edge_metadata`
   - `upsert_node` / `remove_node`
2. Add `_tx` variants of the same operations for caller-owned transaction
   composition.
3. Add batch command API `apply_graph_delta_batch_tx` for mixed operations across
   multiple graph IDs within one SQL transaction.
4. Add optional optimistic concurrency on write payloads via
   `expected_updated_at`.
5. Add task-centric lookup APIs:
   - node by `external_id` (from node metadata)
   - incident edges by node ID and by `external_id`
6. Add JSONB metadata filtering APIs for nodes/edges using `@>` containment.
7. Add metadata indexes for performance:
   - GIN index on `graph.nodes.metadata`
   - GIN index on `graph.edges.metadata`
   - expression index on `(graph.nodes.metadata ->> 'external_id')`
8. Canonicalize metadata at boundaries with typed API/DB shims:
   - API-facing metadata is normalized to `camelCase`
   - DB-facing metadata is normalized to `snake_case`
   - conflicting keys after normalization are rejected
   - non-object metadata payloads are rejected
9. Add atomic node reparent/detach mutation for tree-style `subtask_of` workflows:
   - `reparent_node` / `reparent_node_tx`
   - validates graph invariants against final edge state instead of
     remove-then-add intermediate states
   - supports optional edge metadata override when assigning a new parent

## Invariants and Auth

- Existing graph invariants remain enforced for all mutation paths.
- Existing auth behavior remains unchanged:
  - read routes use graph read access roles
  - mutation routes use graph update access roles
- Stale optimistic writes return conflict (`error.code = stale_graph_update`).

## API Surface Added

- `PUT /graph/{graph_id}/replace` (guarded replace)
- `POST /graph/{graph_id}/node/upsert`
- `POST /graph/{graph_id}/node/remove`
- `POST /graph/{graph_id}/node/reparent`
- `POST /graph/{graph_id}/edge/add`
- `POST /graph/{graph_id}/edge/remove`
- `POST /graph/{graph_id}/edge/upsert-metadata`
- `GET /graph/{graph_id}/node/by-external-id/{external_id}`
- `GET /graph/{graph_id}/edge/incident/node/{node_id}`
- `GET /graph/{graph_id}/edge/incident/external-id/{external_id}`
- `POST /graph/{graph_id}/nodes/query-metadata`
- `POST /graph/{graph_id}/edges/query-metadata`

## Caveats

- `remove_node` currently disallows removing the final node in a graph.
- `node/reparent` with `newParentNodeId = null` (detach) may still fail for
  tree graphs if the final detached state violates rooted/connected invariants.
- `external_id` semantics are caller-defined and not globally unique unless the
  caller enforces uniqueness.
- Metadata payloads must be JSON objects; scalar/array metadata is rejected.
