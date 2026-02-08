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
