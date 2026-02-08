pub mod algorithms;
#[cfg(feature = "api")]
pub mod api;
#[cfg(feature = "sqlx")]
pub mod db;
pub mod error;
pub mod models;

pub mod prelude {
    pub use crate::algorithms::{adjacency_map, has_cycle, topological_sort};
    #[cfg(feature = "api")]
    pub use crate::api::{GraphApp, HasGraphPolicyAdminRoles, HasPool};
    #[cfg(feature = "sqlx")]
    pub use crate::db::{
        authorize_group_policy_edit, create_graph, create_graph_tables, delete_graph, get_graph,
        list_graphs, list_group_allowed_roles, set_group_allowed_roles, update_graph,
    };
    pub use crate::error::{ErrorKind, LibError, Result};
    pub use crate::models::{
        CreateGraphPayload, DirectedGraph, GraphEdge, GraphId, GraphNode, GraphNodeId,
        GraphSummary, GroupGraphPermissions, ListGraphsQuery, NewGraphEdge, NewGraphNode, Paged,
        UpdateGraphPayload, UpdateGroupGraphPermissionsPayload,
    };
    pub use subseq_auth::group_id::GroupId;
    pub use subseq_auth::user_id::UserId;
}
