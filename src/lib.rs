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
        add_edge, add_edge_tx, apply_graph_delta_batch_tx, authorize_group_permission,
        create_graph, create_graph_tables, delete_graph, find_node_by_external_id, get_graph,
        list_graph_edges_by_metadata, list_graph_nodes_by_metadata, list_graphs,
        list_group_allowed_roles, list_incident_edges_for_external_id,
        list_incident_edges_for_node, remove_edge, remove_edge_tx, remove_node, remove_node_tx,
        set_group_allowed_roles, update_graph, update_graph_with_guard, upsert_edge_metadata,
        upsert_edge_metadata_tx, upsert_node, upsert_node_tx,
    };
    pub use crate::error::{ErrorKind, LibError, Result};
    pub use crate::invariants::{
        GraphMutationIndex, ensure_graph_invariants, graph_invariant_violations,
    };
    pub use crate::models::{
        AddEdgePayload, CreateGraphPayload, DirectedGraph, EdgeMutationCheckResponse,
        EdgeMutationPayload, GraphDeltaCommand, GraphDeltaOperation, GraphEdge, GraphId,
        GraphInvariantInput, GraphInvariantViolation, GraphKind, GraphNode, GraphNodeId,
        GraphSummary, GroupGraphPermissions, GuardedUpdateGraphPayload, ListGraphsQuery,
        MetadataFilterPayload, NewGraphEdge, NewGraphNode, Paged, RemoveEdgePayload,
        RemoveNodePayload, UpdateGraphPayload, UpdateGroupGraphPermissionsPayload,
        UpsertEdgeMetadataPayload, UpsertNodePayload, ValidateGraphEdgesPayload,
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
