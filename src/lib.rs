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
    pub use crate::api::{GraphApp, HasPool};
    #[cfg(feature = "sqlx")]
    pub use crate::db::{
        create_graph, create_graph_tables, create_graph_with_roles, delete_graph,
        delete_graph_with_roles, get_graph, get_graph_with_roles, list_graphs,
        list_graphs_with_roles, update_graph, update_graph_with_roles,
    };
    pub use crate::error::{ErrorKind, LibError, Result};
    pub use crate::models::{
        CreateGraphPayload, DirectedGraph, GraphEdge, GraphId, GraphNode, GraphNodeId,
        GraphSummary, ListGraphsQuery, NewGraphEdge, NewGraphNode, Paged, UpdateGraphPayload,
    };
    pub use subseq_auth::group_id::GroupId;
    pub use subseq_auth::user_id::UserId;
}
