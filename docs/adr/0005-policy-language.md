# ADR-0005: Policy language and evaluation model

Status: accepted (2026-11-22)

## Context

OpenSASE enforces security policy across several data-plane enforcement points:
- the mobile and desktop Client (local on-device firewall and DNS proxy);
- the Edge (firewall, DNS filtering, ZTNA private application brokering, web inspection, SaaS control, and DLP);
- the Control Plane decision API (`POST /v1/decide` for deferred flows).

Earlier proposals suggested embedding a general-purpose policy engine such as OPA/Rego, compiling policy into decision tables, or introducing a custom domain-specific language (DSL).

Policy evaluation sits on latency-critical paths: every packet flow and every DNS lookup must be evaluated quickly and predictably. Furthermore:
- The evaluator must run within the Client core built with gomobile, where runtime binary size and memory overhead are constrained.
- The web portal must display and edit policy rules through structured forms.
- Administrators need simple programmatic management through `opensasectl policy get/set`.
- Policy updates are distributed as signed, versioned snapshots from the Control Plane to Edges and devices.

## Decision

Keep tenant policy as structured JSON (the `TenantPolicy` document), validated by `policy.Compile` on the Control Plane. Do not adopt OPA/Rego or another policy language runtime now.

Key reasons for this decision:
- **Single shared evaluator**: One Go evaluator compiles directly into the Edge, Client, and gomobile core. It requires no external runtime, virtual machine, or interpreter.
- **Deterministic and bounded execution**: Packet and DNS filtering paths execute with predictable algorithmic bounds and fixed memory. Evaluation does not suffer from loops, recursion, or unpredictable execution time.
- **Form-friendly authoring**: The portal renders and edits policy fields with web forms. It saves updates directly via `PUT /v1/admin/tenants/{t}/policy` with `If-Match` concurrency control.
- **Compact signed snapshots**: Structured JSON snapshots remain small. Signing them, long-polling them from the Control Plane and caching them on Edges and devices costs little.
- **Actionable validation errors**: `policy.Compile` rejects malformed input early on the Control Plane and names the exact JSON field path in error responses (for example, `web.rules[0].domains`).

We publish a JSON Schema (draft 2020-12) at `docs/schema/tenant-policy.schema.json` for external tooling, IDE validation, and schema-aware editors. `policy.Compile` remains the authoritative validator: the schema documents the shape, while `policy.Compile` enforces semantics such as port and CIDR ranges, reference integrity, and RE2 regex validity.

Future policy features (such as conditions, exceptions, or schedules) will be added as new optional JSON fields with explicit semantics. The Control Plane rejects unknown fields on write, so a typo never becomes a silently ignored rule. An Edge or Client older than a new field ignores it; a new field must therefore be defined so that ignoring it is safe, or the Control Plane must hold it back until the Edges that receive it support it.

Migration requires no effort because existing policies already use this JSON format. Management tooling includes `opensasectl policy get/set`, the portal editor with ETag/`If-Match`, and the JSON Schema.

If customer requirements eventually demand logic that declarative fields cannot express, we will revisit this decision. If revisited, we will introduce an ahead-of-time compiler on the Control Plane that compiles the higher-level language into this JSON format, rather than running a language interpreter on the data plane.

## Consequences

- The Edge and Client run a lightweight, self-contained Go policy evaluator without third-party interpreter dependencies.
- Mobile clients avoid extra memory footprint and binary bloat inside the gomobile library.
- Editors and continuous integration pipelines can validate policy documents against `docs/schema/tenant-policy.schema.json` before sending them to the API.
- All policy changes continue to be validated synchronously by `policy.Compile` before persistence.
- Adding new policy capabilities requires updating Go structs, schema definitions, and compiler validation logic.

### Alternatives considered

- **OPA/Rego**: Requires embedding a Rego interpreter or WebAssembly runtime in the Edge and Client. This increases binary size, complicates gomobile builds on mobile targets, and risks unbounded evaluation latency on packet paths.
- **CEL (Common Expression Language)**: Provides bounded execution, but still requires an expression evaluation runtime across Go and mobile environments. CEL expressions are also harder to map bidirectionally to portal form controls than structured JSON fields.
- **Custom DSL**: Requires creating and maintaining a custom parser, compiler, syntax specification, and language tooling without offering clear operational advantages over structured JSON and JSON Schema.
