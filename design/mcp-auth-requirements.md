# Agent-to-MCP Auth Requirements (v0.1)

## Purpose
Define requirements for a separate MCP service codebase so agent-initiated tool calls execute with correct user authorization (`UserId`) and least privilege.

## Goals
1. Preserve end-user identity from app -> agent -> MCP.
2. Enforce authorization in MCP using existing `subseq_auth` patterns.
3. Avoid trusting model/tool arguments for identity.
4. Support long-running tasks without auth dropouts.

## Non-Goals
1. Replacing your primary IdP (for example Cognito).
2. Defining tool-specific business logic for every domain.

## Architecture Requirements
1. User identity source MUST remain the primary IdP.
2. Agent service MUST validate user auth before invoking MCP.
3. MCP service MUST authenticate every request/connection and derive trusted `UserId` from token claims.
4. MCP tool payloads MUST NOT include trusted identity fields (`user_id`, `group_id`) as authorization source.

## Token and Session Requirements
1. MCP calls MUST carry auth context via `Authorization: Bearer <token>` (HTTP) or authenticated WS session.
2. Preferred path: agent performs token exchange with `subseq_auth` to mint short-lived MCP-scoped token.
3. MCP token MUST include `iss`, `aud`, `sub`, `exp`, `iat`, and `scope`; SHOULD include `jti`, `azp`/`client_id`, and optional `thread_id`.
4. `aud` MUST be MCP-specific.
5. Tokens MUST be short-lived and refreshable.
6. Agent MUST refresh before expiry and retry once on `401` for safe/idempotent calls.

## Authorization Requirements
1. MCP middleware MUST inject `actor: UserId` into request context.
2. Tool handlers MUST authorize via domain permission checks (for graph: hard-coded roles and scope checks).
3. Missing permission failures MUST return machine-readable auth errors compatible with `subseq_auth` error shape (for example `missing_scope_check` details).

## Security Requirements
1. Service-to-service traffic MUST use TLS.
2. Agent MUST NOT mint arbitrary user tokens directly; delegation MUST be policy-controlled (token exchange/OBO).
3. MCP MUST reject tokens with wrong issuer, audience, or expired timestamps.
4. Sensitive tokens MUST NOT be logged.
5. Replay mitigation SHOULD be implemented (`jti` + short TTL).

## Operational Requirements
1. Audit log MUST capture caller user id, tool name, action, auth decision, and reason code.
2. Metrics MUST include auth success/fail counts, token refresh count, `401` retry count, and permission-denied counts by code/scope.
3. Tracing MUST correlate user request -> agent tool call -> MCP authorization decision.

## Auth-Service Interface Requirements
1. `subseq_auth` SHOULD expose delegated-token issuance for MCP audience.
2. `subseq_auth` MUST provide verification material for MCP (JWKS or introspection).
3. Error contracts MUST be stable and versioned.

## Testing Requirements
1. Unit tests for middleware claim validation and context injection.
2. Integration tests for token exchange, expiry, refresh, and retry.
3. Authorization tests for allowed/denied scope checks with machine-readable failure payloads.
4. Negative tests for forged `user_id` in tool args.

## Phased Delivery
1. Phase 1: Agent forwards validated user token to MCP; MCP validates and enforces auth.
2. Phase 2: Introduce delegated MCP-scoped token exchange in `subseq_auth`.
3. Phase 3: Tighten scopes, replay protection, and full audit/metrics gates.

## Open Decisions
1. Exact token exchange mechanism in `subseq_auth` (JWT mint vs introspection-only).
2. WS re-auth strategy and refresh cadence.
3. Minimum scope taxonomy per MCP tool set.
