ALTER TABLE graph.graphs
ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'directed';

UPDATE graph.graphs
SET kind = 'directed'
WHERE kind IS NULL;

ALTER TABLE graph.graphs
DROP CONSTRAINT IF EXISTS graph_graphs_kind_check;

ALTER TABLE graph.graphs
ADD CONSTRAINT graph_graphs_kind_check
CHECK (kind IN ('tree', 'dag', 'directed'));

CREATE INDEX IF NOT EXISTS idx_graph_graphs_kind
    ON graph.graphs (kind);
