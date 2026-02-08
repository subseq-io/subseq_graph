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

const GRAPH_READ_ACCESS_ROLES: &[&str] = &[
    GRAPH_ROLE_READ,
    GRAPH_ROLE_CREATE,
    GRAPH_ROLE_UPDATE,
    GRAPH_ROLE_DELETE,
];

const GRAPH_CREATE_ACCESS_ROLES: &[&str] = &[GRAPH_ROLE_CREATE];
const GRAPH_UPDATE_ACCESS_ROLES: &[&str] = &[GRAPH_ROLE_UPDATE];
const GRAPH_DELETE_ACCESS_ROLES: &[&str] = &[GRAPH_ROLE_DELETE];
const GRAPH_PERMISSIONS_READ_ACCESS_ROLES: &[&str] =
    &[GRAPH_ROLE_PERMISSIONS_READ, GRAPH_ROLE_PERMISSIONS_UPDATE];
const GRAPH_PERMISSIONS_UPDATE_ACCESS_ROLES: &[&str] = &[GRAPH_ROLE_PERMISSIONS_UPDATE];

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

/// Roles that can read/list graphs. Mutating roles imply read access.
pub const fn graph_read_access_roles() -> &'static [&'static str] {
    GRAPH_READ_ACCESS_ROLES
}

pub const fn graph_create_access_roles() -> &'static [&'static str] {
    GRAPH_CREATE_ACCESS_ROLES
}

pub const fn graph_update_access_roles() -> &'static [&'static str] {
    GRAPH_UPDATE_ACCESS_ROLES
}

pub const fn graph_delete_access_roles() -> &'static [&'static str] {
    GRAPH_DELETE_ACCESS_ROLES
}

pub const fn graph_permissions_read_access_roles() -> &'static [&'static str] {
    GRAPH_PERMISSIONS_READ_ACCESS_ROLES
}

pub const fn graph_permissions_update_access_roles() -> &'static [&'static str] {
    GRAPH_PERMISSIONS_UPDATE_ACCESS_ROLES
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use uuid::Uuid;

    use super::*;

    #[test]
    fn graph_read_access_roles_include_mutating_roles() {
        let roles: HashSet<&str> = graph_read_access_roles().iter().copied().collect();

        assert!(roles.contains(graph_read_role()));
        assert!(roles.contains(graph_create_role()));
        assert!(roles.contains(graph_update_role()));
        assert!(roles.contains(graph_delete_role()));
    }

    #[test]
    fn graph_permissions_read_access_includes_permissions_update() {
        let roles: HashSet<&str> = graph_permissions_read_access_roles()
            .iter()
            .copied()
            .collect();

        assert!(roles.contains(graph_permissions_read_role()));
        assert!(roles.contains(graph_permissions_update_role()));
    }

    #[test]
    fn graph_scope_id_helpers_match_expected_values() {
        let group_id = GroupId(Uuid::new_v4());

        assert_eq!(graph_role_scope(), "graph");
        assert_eq!(graph_role_scope_id_global(), "global");
        assert_eq!(
            graph_role_scope_id_for_group(group_id),
            group_id.to_string()
        );
    }

    #[test]
    fn graph_permission_role_validation_matches_known_values() {
        assert!(is_graph_permission_role(graph_read_role()));
        assert!(is_graph_permission_role(graph_permissions_update_role()));
        assert!(!is_graph_permission_role("graph_super_admin"));
    }
}
