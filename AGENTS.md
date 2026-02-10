# Agent Guidelines (subseq_graph)

This file stores durable, repo-specific guardrails for subseq_graph.

## Architecture
- Keep subseq_graph on the flattened sqlx architecture (`api.rs`, `db.rs`, `models.rs`) unless a deliberate redesign is approved.
- Keep core graph domain focused on graphs, nodes, and edges; avoid reintroducing legacy Diesel/thread/pattern modeling patterns.

## Authorization Model
- Enforce authorization predicates directly in mutation SQL (`UPDATE`/`DELETE`), not as check-then-act pre-reads.
- Treat `rows_affected = 0` as forbidden/not-found after an existence check.
- Keep scope checks aligned with scoped roles in `subseq_auth`.
- Keep canonical graph boundaries (`graph_read`, `graph_create`, `graph_update`, `graph_delete`, `graph_permissions_read`, `graph_permissions_update`) centralized in permissions helpers.
- Keep group-role checks strict on group scope identity (`scope_id = group_id`); do not introduce implicit global fallback for group role grants.
- Keep read/list checks using access role sets where write-capable roles imply read.

## API and Error Contract
- Keep structured authorization denial payloads using shared `subseq_auth` primitives.
- Preserve `missing_scope_check` denial semantics with required role/scope details in error payloads.

## Mutation Surface
- Keep delta mutation APIs and tx variants available for add/remove edge, node upsert/remove, edge metadata upsert/remove, and batch execution.
- Keep optimistic concurrency support via `expected_updated_at` where stale-graph protection is required.
- Preserve graph-side reparent/detach support with final-state invariant validation for tree operations.

## Verification and Safety
- Keep unit-test coverage for scope semantics, role inheritance/access-role sets, and structured error payload shape.
- When changing permission or mutation semantics, update tests in the same round.
