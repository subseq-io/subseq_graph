CREATE SCHEMA IF NOT EXISTS graph;

CREATE TABLE IF NOT EXISTS graph.graphs (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    owner_group_id UUID REFERENCES auth.groups(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    description TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_graph_graphs_owner_user_id
    ON graph.graphs (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_graph_graphs_owner_group_id
    ON graph.graphs (owner_group_id)
    WHERE owner_group_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS graph.nodes (
    id UUID PRIMARY KEY,
    graph_id UUID NOT NULL REFERENCES graph.graphs(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (graph_id, id)
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_graph_id
    ON graph.nodes (graph_id);

CREATE TABLE IF NOT EXISTS graph.edges (
    graph_id UUID NOT NULL REFERENCES graph.graphs(id) ON DELETE CASCADE,
    from_node_id UUID NOT NULL,
    to_node_id UUID NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (graph_id, from_node_id, to_node_id),
    CONSTRAINT graph_edges_from_fk
        FOREIGN KEY (graph_id, from_node_id)
        REFERENCES graph.nodes(graph_id, id)
        ON DELETE CASCADE,
    CONSTRAINT graph_edges_to_fk
        FOREIGN KEY (graph_id, to_node_id)
        REFERENCES graph.nodes(graph_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_graph_id
    ON graph.edges (graph_id);
