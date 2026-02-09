# Frontend Graph API Spec

This document is for frontend implementation against `subseq_graph`, including
example-server usage and `@xyflow/react` integration guidance.

## 1) Environment And Auth

### Base URL

- Production: your deployed graph service base URL.
- Local constrained example:
  - run: `DATABASE_URL=postgres://... cargo run --example graph_api_server`
  - default bind: `http://127.0.0.1:4010`
- API prefix for all routes in this document: `/api/v1`

### Auth

All routes require an authenticated user except `GET /api/v1/healthz`.

- Production: standard auth middleware / bearer flow.
- Example server (`examples/graph_api_server.rs`):
  - `x-dev-user-id` (UUID, optional by default)
  - `x-dev-email` (optional)
  - `x-dev-username` (optional)
  - `GRAPH_EXAMPLE_REQUIRE_DEV_HEADER=true` to force `x-dev-user-id`.

## 2) Response And Error Contract

### Error Envelope

All API errors return:

```json
{
  "error": {
    "code": "string",
    "message": "string",
    "details": {
      "type": "missing_scope_check",
      "scope": "string",
      "scopeId": "string",
      "requiredAnyRoles": ["string"]
    }
  }
}
```

`details` is optional and appears for scoped auth denials.

### Status Mapping

- `400`: invalid input / invariant violation
- `403`: forbidden
- `404`: not found
- `409`: optimistic concurrency conflict (`stale_graph_update`)
- `500`: internal/database error

## 3) Core Models

### `GraphKind`

- `"tree" | "dag" | "directed"`

### `DirectedGraph`

```json
{
  "id": "uuid",
  "ownerUserId": "uuid",
  "ownerGroupId": "uuid|null",
  "kind": "tree|dag|directed",
  "name": "string",
  "description": "string|null",
  "metadata": {},
  "createdAt": "timestamp",
  "updatedAt": "timestamp",
  "nodes": [
    { "id": "uuid", "label": "string", "metadata": {} }
  ],
  "edges": [
    { "fromNodeId": "uuid", "toNodeId": "uuid", "metadata": {} }
  ]
}
```

### Metadata Contract

- API metadata is camelCase JSON object keys.
- Non-object metadata is rejected (`400`).
- Key collisions after canonicalization are rejected (`400`).

## 4) Routes

## `GET /api/v1/healthz` (example server helper)

- Response `200`:

```json
{ "ok": true }
```

## `GET /api/v1/example/whoami` (example server helper)

- Response `200`:

```json
{
  "userId": "uuid",
  "username": "string|null"
}
```

## `POST /api/v1/graph`

Create graph. Returns full graph.

Request:

```json
{
  "kind": "tree|dag|directed",
  "name": "string",
  "description": "string|null",
  "metadata": {},
  "ownerGroupId": "uuid|null",
  "nodes": [
    { "id": "uuid|null", "label": "string", "metadata": {} }
  ],
  "edges": [
    { "fromNodeId": "uuid", "toNodeId": "uuid", "metadata": {} }
  ]
}
```

Response: `201` `DirectedGraph`

Notes:

- At least one node required.
- Graph invariants enforced by `kind`.

## `GET /api/v1/graph`

List graphs visible to user.

Query:

- `page` (optional, default `1`)
- `limit` (optional, default `25`, max `200`)

Response `200`:

```json
{
  "page": 1,
  "limit": 25,
  "items": [
    {
      "id": "uuid",
      "ownerUserId": "uuid",
      "ownerGroupId": "uuid|null",
      "kind": "tree|dag|directed",
      "name": "string",
      "description": "string|null",
      "createdAt": "timestamp",
      "updatedAt": "timestamp",
      "nodeCount": 0,
      "edgeCount": 0
    }
  ]
}
```

## `GET /api/v1/graph/{graph_id}`

Get full graph.

Response `200`: `DirectedGraph`

## `PUT /api/v1/graph/{graph_id}`

Full replace update.

Request: same shape as `POST /api/v1/graph` without `id`.

Response `200`: `DirectedGraph`

## `PUT /api/v1/graph/{graph_id}/replace`

Guarded full replace (optimistic concurrency).

Request:

```json
{
  "graph": {
    "kind": "tree|dag|directed",
    "name": "string",
    "description": "string|null",
    "metadata": {},
    "ownerGroupId": "uuid|null",
    "nodes": [{ "id": "uuid|null", "label": "string", "metadata": {} }],
    "edges": [{ "fromNodeId": "uuid", "toNodeId": "uuid", "metadata": {} }]
  },
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: `DirectedGraph`

Conflict:

- `409` with `error.code = "stale_graph_update"` if `expectedUpdatedAt` mismatches.

## `DELETE /api/v1/graph/{graph_id}`

Delete graph.

Response `204` (empty body)

## `POST /api/v1/graph/{graph_id}/node/upsert`

Create/update one node.

Request:

```json
{
  "nodeId": "uuid|null",
  "label": "string",
  "metadata": {},
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: updated `DirectedGraph`

## `POST /api/v1/graph/{graph_id}/node/remove`

Remove one node and incident edges.

Request:

```json
{
  "nodeId": "uuid",
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: updated `DirectedGraph`

Notes:

- Cannot remove the final remaining node.

## `POST /api/v1/graph/{graph_id}/node/reparent`

Atomic parent-link mutation for tree/subtask flows.

Request:

```json
{
  "nodeId": "uuid",
  "newParentNodeId": "uuid|null",
  "metadata": {},
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: updated `DirectedGraph`

Notes:

- Validates on final state, avoiding remove-first/add-first intermediate failures.
- `newParentNodeId = null` means detach.
- `metadata` is only valid when `newParentNodeId` is non-null.
- Tree detach can still fail if final state violates rooted/connected invariants.

## `POST /api/v1/graph/{graph_id}/edge/add`

Add one edge.

Request:

```json
{
  "fromNodeId": "uuid",
  "toNodeId": "uuid",
  "metadata": {},
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: updated `DirectedGraph`

## `POST /api/v1/graph/{graph_id}/edge/remove`

Remove one edge.

Request:

```json
{
  "fromNodeId": "uuid",
  "toNodeId": "uuid",
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: updated `DirectedGraph`

## `POST /api/v1/graph/{graph_id}/edge/upsert-metadata`

Set metadata for one edge (creates edge if absent and valid).

Request:

```json
{
  "fromNodeId": "uuid",
  "toNodeId": "uuid",
  "metadata": {},
  "expectedUpdatedAt": "timestamp|null"
}
```

Response `200`: updated `DirectedGraph`

## `GET /api/v1/graph/{graph_id}/node/by-external-id/{external_id}`

Lookup node by metadata `externalId`.

Response:

- `200`: `GraphNode`
- `404`: not found

## `GET /api/v1/graph/{graph_id}/edge/incident/node/{node_id}`

List incident edges for node.

Response `200`: `GraphEdge[]`

## `GET /api/v1/graph/{graph_id}/edge/incident/external-id/{external_id}`

List incident edges by node external ID.

Response `200`: `GraphEdge[]` (empty array if node not found)

## `POST /api/v1/graph/{graph_id}/nodes/query-metadata`

Filter nodes by JSON containment.

Request:

```json
{ "metadataContains": {} }
```

Response `200`: `GraphNode[]`

## `POST /api/v1/graph/{graph_id}/edges/query-metadata`

Filter edges by JSON containment.

Request:

```json
{ "metadataContains": {} }
```

Response `200`: `GraphEdge[]`

## `POST /api/v1/graph/validate`

Validate candidate graph content without writing.

Request:

```json
{
  "kind": "tree|dag|directed",
  "nodes": [{ "id": "uuid|null", "label": "string", "metadata": {} }],
  "edges": [{ "fromNodeId": "uuid", "toNodeId": "uuid", "metadata": {} }]
}
```

Response `200`:

```json
{
  "valid": true,
  "violations": [
    {
      "type": "unknown_node_reference|self_loop|cycle_detected|in_degree_exceeded|invalid_root_count|disconnected_tree"
    }
  ]
}
```

Violation fields use `snake_case`.

## `POST /api/v1/graph/{graph_id}/validate/add-edge`

Preflight check for one add-edge mutation.

Request:

```json
{
  "fromNodeId": "uuid",
  "toNodeId": "uuid"
}
```

Response `200`:

```json
{
  "valid": true,
  "wouldIntroduceViolation": false,
  "wouldIsolateSubgraph": false,
  "violations": []
}
```

## `POST /api/v1/graph/{graph_id}/validate/remove-edge`

Preflight check for one remove-edge mutation.

Request:

```json
{
  "fromNodeId": "uuid",
  "toNodeId": "uuid"
}
```

Response `200`: same shape as add-edge preflight.

## `GET /api/v1/graph/group/{group_id}/permissions`

Read group graph-permission roles.

Response `200`:

```json
{
  "groupId": "uuid",
  "allowedRoles": ["graph_read", "graph_update"]
}
```

## `PUT /api/v1/graph/group/{group_id}/permissions`

Set group graph-permission roles.

Request:

```json
{
  "allowedRoles": ["graph_read", "graph_update", "graph_permissions_update"]
}
```

Response `200`:

```json
{
  "groupId": "uuid",
  "allowedRoles": ["graph_read", "graph_update", "graph_permissions_update"]
}
```

## 5) Frontend Primer (`@xyflow/react`)

## Mapping API -> React Flow

1. `DirectedGraph.nodes[]` -> `Node[]`
2. `DirectedGraph.edges[]` -> `Edge[]`
3. Use graph node UUID as React Flow `node.id`.
4. Use stable edge id like `${fromNodeId}->${toNodeId}`.
5. Preserve backend IDs in `data` for mutation calls.

Example mapping:

```ts
import type { Node, Edge } from "@xyflow/react";

function toFlow(graph: DirectedGraph): { nodes: Node[]; edges: Edge[] } {
  return {
    nodes: graph.nodes.map((n) => ({
      id: n.id,
      position: {
        x: n.metadata?.ui?.x ?? 0,
        y: n.metadata?.ui?.y ?? 0,
      },
      data: { label: n.label, metadata: n.metadata },
      type: "default",
    })),
    edges: graph.edges.map((e) => ({
      id: `${e.fromNodeId}->${e.toNodeId}`,
      source: e.fromNodeId,
      target: e.toNodeId,
      data: { metadata: e.metadata },
      type: "default",
    })),
  };
}
```

## Interaction Strategy

1. Load graph once (`GET /api/v1/graph/{id}`) and hydrate React Flow state.
2. Use preflight endpoints before committing topology mutations:
   - edge connect: `/validate/add-edge`
   - edge delete: `/validate/remove-edge`
3. Use mutation endpoints for committed changes:
   - connect edge: `/edge/add`
   - delete edge: `/edge/remove`
   - move subtask parent in tree: `/node/reparent`
   - edit labels/metadata: `/node/upsert`, `/edge/upsert-metadata`
4. On each mutation success, replace local state with returned full graph.

## Concurrency Strategy

Use `graph.updatedAt` as optimistic guard:

1. Send `expectedUpdatedAt` with mutating calls.
2. On `409 stale_graph_update`, refetch graph and replay user action if needed.

## Suggested UX Behavior

1. For edge creation/removal, run preflight and show invariant errors before commit.
2. For tree reparent drag/drop, call `/node/reparent` (not remove+add edge).
3. For drag position persistence, store UI coordinates in node metadata via
   debounced `/node/upsert`.
4. For `403 missing_scope_check`, disable edit controls and show missing role info.

## Suggested Query Keying (React Query)

1. `["graph", graphId]` for full graph
2. `["graphs", page, limit]` for list
3. invalidate `["graph", graphId]` after any mutation
4. optionally update cache directly using returned `DirectedGraph`
