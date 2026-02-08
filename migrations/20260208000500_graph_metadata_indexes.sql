CREATE INDEX IF NOT EXISTS idx_graph_nodes_metadata_gin
    ON graph.nodes
    USING GIN (metadata);

CREATE INDEX IF NOT EXISTS idx_graph_edges_metadata_gin
    ON graph.edges
    USING GIN (metadata);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_external_id
    ON graph.nodes ((metadata ->> 'external_id'))
    WHERE metadata ? 'external_id';
