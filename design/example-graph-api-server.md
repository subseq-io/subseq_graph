# Example Graph API Server

## Goal

Provide a constrained local Axum server for frontend graph visualizer work that
can exercise graph API routes against a real Postgres database without wiring a
full OIDC identity provider.

## Server Entry Point

- `examples/graph_api_server.rs`

## Runtime Behavior

1. Reads `DATABASE_URL` from environment (required).
2. Connects with SQLx and runs graph migrations via `create_graph_tables`.
3. Serves graph API routes from `subseq_graph::api::routes::<ExampleApp>()`.
4. Mounts all routes under `/api/v1`.
5. Keeps `/api/v1/healthz` public for probes and applies dev auth middleware to
   graph and helper routes that require identity.
6. Auto-provisions `auth.users` rows for dev-auth identities (default user and
   any `x-dev-user-id` override) so graph writes do not fail on auth FK checks.

## Dev Auth Shim

Headers:

- `x-dev-user-id` (UUID, optional unless forced)
- `x-dev-email` (optional)
- `x-dev-username` (optional)

Defaults:

- user id from `GRAPH_EXAMPLE_DEFAULT_USER_ID` or
  `00000000-0000-0000-0000-000000000001`
- email from `GRAPH_EXAMPLE_DEFAULT_EMAIL` or
  `graph-example@example.local`
- username from `GRAPH_EXAMPLE_DEFAULT_USERNAME` or `graph-example`

Constraint toggle:

- `GRAPH_EXAMPLE_REQUIRE_DEV_HEADER=true` forces callers to provide
  `x-dev-user-id` on each request.

## Run

```bash
DATABASE_URL=postgres://... cargo run --example graph_api_server
```

Optional bind override:

```bash
GRAPH_EXAMPLE_BIND=127.0.0.1:4010
```

## Notes

- This example is intentionally not a production auth setup.
- It exists to support local UI/interaction testing of graph API actions.
