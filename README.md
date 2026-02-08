# subseq_graph

## Graph Permission Model

Group-owned graph access is authorized through `subseq_auth` scoped role tables:

- `auth.user_roles` for direct user grants.
- `auth.group_roles` for group-wide grants.

Graph permission checks require:

1. Active membership in the target group (`auth.group_memberships` + active user/group).
2. A matching graph permission role in either `auth.user_roles` or `auth.group_roles`.

### Hard-coded Graph Permission Boundaries

The graph library uses fixed permission role names:

- `graph_read`
- `graph_create`
- `graph_update`
- `graph_delete`
- `graph_permissions_read`
- `graph_permissions_update`

Read inheritance:

- Graph read/list checks accept any of: `graph_read`, `graph_create`, `graph_update`, `graph_delete`.
- Graph-permission read checks accept `graph_permissions_read` or `graph_permissions_update`.

These are exposed via `subseq_graph::permissions` helpers so app code can avoid string literals.

```rust
use subseq_graph::permissions;

let scope = permissions::graph_role_scope(); // "graph"
let global_scope_id = permissions::graph_role_scope_id_global(); // "global"
let update_role = permissions::graph_update_role(); // "graph_update"
let all_graph_roles = permissions::all_graph_permission_roles();
let graph_read_access = permissions::graph_read_access_roles();
```

### Scope IDs

For group-scoped graph permissions:

- `scope = "graph"`
- `scope_id = group_id.to_string()`
- Applies to:
  - `auth.group_roles` grants for that specific group.
  - `auth.user_roles` direct user grants for that specific group.

For global graph permissions:

- `scope = "graph"`
- `scope_id = "global"`
- Applies to:
  - `auth.user_roles` direct user grants.
  - Not used for `auth.group_roles` in graph authorization checks.

### Group Permission Route Behavior

`/graph/group/{group_id}/permissions` reads/writes graph permission roles in
`auth.group_roles` for that group scope. Only the hard-coded graph permission role names above are accepted.

### Programmatic Permission Errors

Graph API errors use the shared auth-layer structured error shape from
`subseq_auth::prelude::structured_error_response`.

When access fails due to missing scope roles, responses use:

- `status = 403`
- `error.code = "missing_scope_check"`
- `error.details.type = "missing_scope_check"`
- `error.details.scope`
- `error.details.scope_id`
- `error.details.required_any_roles`

Example:

```json
{
  "error": {
    "code": "missing_scope_check",
    "message": "You do not have access to this graph",
    "details": {
      "type": "missing_scope_check",
      "scope": "graph",
      "scope_id": "8a529ede-a93d-4b31-861f-d305a7c31f2d",
      "required_any_roles": [
        "graph_read",
        "graph_update"
      ]
    }
  }
}
```

## Agent/MCP Operations

`subseq_graph::operations` provides a high-level surface intended for MCP/tool
handlers so graph logic stays colocated with graph code:

- `GraphOperations::create_graph`
- `GraphOperations::extend_graph` (append nodes/edges to an existing graph)
- `GraphOperations::replace_graph` (full definition replacement)
- `GraphOperations::get_graph`
- `GraphOperations::list_graphs`
- `GraphOperations::delete_graph`
- `GraphOperations::get_group_permissions`
- `GraphOperations::set_group_permissions`
- `GraphOperations::execute` with `GraphOperation` enum for single-dispatch tool handlers

`extend_graph` merges new nodes/edges into the current graph while preserving
existing structure:

- Rejects duplicate node IDs.
- Validates that new edges reference existing or newly-added nodes.
- Deduplicates duplicate edges (existing pair wins).

## MCP Auth Mapping

MCP/tool requests should map to this library by first resolving caller identity
through `subseq_auth` session/token validation, then passing the resulting
trusted `UserId` into `GraphOperations` methods.

Security rule:

- Do not accept `user_id` from model/tool arguments.
- Always derive `actor: UserId` from authenticated request context.

This keeps agent actions aligned with the same role/scope checks used by the
HTTP API.

## Graph Kinds and Invariants

Graphs now persist a `kind` with one of:

- `tree`
- `dag`
- `directed`

Invariant enforcement is applied on graph write paths (`create`, `update`, and
`extend` via update):

- `tree`:
  - no self-loops
  - acyclic
  - in-degree <= 1 for every node
  - exactly one root (in-degree = 0)
  - rooted connectivity (all nodes reachable from the root)
- `dag`:
  - no self-loops
  - acyclic
- `directed`:
  - cycles are allowed

Invariant violations are returned as validation errors (`400`) with a stable
machine-readable `error.code` (for example `graph_dag_cycle`).

## Edge Validation API

`POST /graph/validate` validates a candidate graph structure without mutating
state. It returns machine-readable violation reasons.

Request body:

```json
{
  "kind": "tree",
  "nodes": [{ "id": "uuid", "label": "A" }],
  "edges": [{ "fromNodeId": "uuid", "toNodeId": "uuid" }]
}
```

Low-cost single-mutation checks:

- `POST /graph/{graph_id}/validate/add-edge`
- `POST /graph/{graph_id}/validate/remove-edge`

These use an in-memory mutation index to precompute node/edge topology once, then
evaluate single-edge deltas with targeted checks (for cycle/isolation) instead of
re-running full normalization/write paths.

Request body:

```json
{
  "fromNodeId": "uuid",
  "toNodeId": "uuid"
}
```

Response body:

```json
{
  "valid": false,
  "wouldIntroduceViolation": true,
  "wouldIsolateSubgraph": true,
  "violations": [
    {
      "type": "invalid_root_count",
      "root_count": 2
    }
  ]
}
```

Response body:

```json
{
  "valid": false,
  "violations": [
    {
      "type": "cycle_detected"
    }
  ]
}
```
