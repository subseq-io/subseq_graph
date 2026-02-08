pub mod algorithms;
#[cfg(feature = "api")]
pub mod api;
#[cfg(feature = "sqlx")]
pub mod db;
pub mod error;
pub mod invariants;
pub mod models;
#[cfg(feature = "sqlx")]
pub mod operations;
pub mod permissions;

pub mod prelude {
    pub use crate::algorithms::{adjacency_map, has_cycle, topological_sort};
    #[cfg(feature = "api")]
    pub use crate::api::{GraphApp, HasPool};
    #[cfg(feature = "sqlx")]
    pub use crate::db::{
        authorize_group_permission, create_graph, create_graph_tables, delete_graph, get_graph,
        list_graphs, list_group_allowed_roles, set_group_allowed_roles, update_graph,
    };
    pub use crate::error::{ErrorKind, LibError, Result};
    pub use crate::invariants::{ensure_graph_invariants, graph_invariant_violations};
    pub use crate::models::{
        CreateGraphPayload, DirectedGraph, GraphEdge, GraphId, GraphInvariantInput,
        GraphInvariantViolation, GraphKind, GraphNode, GraphNodeId, GraphSummary,
        GroupGraphPermissions, ListGraphsQuery, NewGraphEdge, NewGraphNode, Paged,
        UpdateGraphPayload, UpdateGroupGraphPermissionsPayload, ValidateGraphEdgesPayload,
        ValidateGraphEdgesResponse,
    };
    #[cfg(feature = "sqlx")]
    pub use crate::operations::{
        ExtendGraphPayload, GraphOperation, GraphOperationResult, GraphOperations,
    };
    pub use crate::permissions::{
        all_graph_permission_roles, graph_create_access_roles, graph_create_role,
        graph_delete_access_roles, graph_delete_role, graph_permissions_read_access_roles,
        graph_permissions_read_role, graph_permissions_update_access_roles,
        graph_permissions_update_role, graph_read_access_roles, graph_read_role, graph_role_scope,
        graph_role_scope_id_for_group, graph_role_scope_id_global, graph_update_access_roles,
        graph_update_role,
    };
    pub use subseq_auth::group_id::GroupId;
    pub use subseq_auth::user_id::UserId;
}
