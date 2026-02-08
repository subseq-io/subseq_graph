CREATE TABLE IF NOT EXISTS graph.group_allowed_roles (
    group_id UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_graph_group_allowed_roles_group_id
    ON graph.group_allowed_roles (group_id);
