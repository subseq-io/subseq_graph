use subseq_auth::group_id::GroupId;

/// Scope used for graph permission grants in `auth.user_roles` and `auth.group_roles`.
pub const GRAPH_ROLE_SCOPE: &str = "graph";

/// Global scope id that applies across all groups for the graph scope.
pub const GRAPH_ROLE_SCOPE_ID_GLOBAL: &str = "global";

/// Can read group-owned graphs.
pub const GRAPH_ROLE_READ: &str = "graph_read";
/// Can create/update ownership into group-owned graphs.
pub const GRAPH_ROLE_CREATE: &str = "graph_create";
/// Can update group-owned graphs.
pub const GRAPH_ROLE_UPDATE: &str = "graph_update";
/// Can delete group-owned graphs.
pub const GRAPH_ROLE_DELETE: &str = "graph_delete";
/// Can view configured graph permission roles for a group.
pub const GRAPH_ROLE_PERMISSIONS_READ: &str = "graph_permissions_read";
/// Can update configured graph permission roles for a group.
pub const GRAPH_ROLE_PERMISSIONS_UPDATE: &str = "graph_permissions_update";

pub const ALL_GRAPH_PERMISSION_ROLES: &[&str] = &[
    GRAPH_ROLE_READ,
    GRAPH_ROLE_CREATE,
    GRAPH_ROLE_UPDATE,
    GRAPH_ROLE_DELETE,
    GRAPH_ROLE_PERMISSIONS_READ,
    GRAPH_ROLE_PERMISSIONS_UPDATE,
];

pub const fn graph_role_scope() -> &'static str {
    GRAPH_ROLE_SCOPE
}

pub const fn graph_role_scope_id_global() -> &'static str {
    GRAPH_ROLE_SCOPE_ID_GLOBAL
}

pub const fn graph_read_role() -> &'static str {
    GRAPH_ROLE_READ
}

pub const fn graph_create_role() -> &'static str {
    GRAPH_ROLE_CREATE
}

pub const fn graph_update_role() -> &'static str {
    GRAPH_ROLE_UPDATE
}

pub const fn graph_delete_role() -> &'static str {
    GRAPH_ROLE_DELETE
}

pub const fn graph_permissions_read_role() -> &'static str {
    GRAPH_ROLE_PERMISSIONS_READ
}

pub const fn graph_permissions_update_role() -> &'static str {
    GRAPH_ROLE_PERMISSIONS_UPDATE
}

pub const fn all_graph_permission_roles() -> &'static [&'static str] {
    ALL_GRAPH_PERMISSION_ROLES
}

/// Graph role grants for a specific group are stored with `scope_id = group_id.to_string()`.
pub fn graph_role_scope_id_for_group(group_id: GroupId) -> String {
    group_id.to_string()
}

pub fn is_graph_permission_role(role_name: &str) -> bool {
    ALL_GRAPH_PERMISSION_ROLES
        .iter()
        .any(|known| *known == role_name)
}
