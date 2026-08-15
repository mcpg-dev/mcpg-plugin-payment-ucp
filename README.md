# Universal Commerce Protocol (UCP) — `dev.mcpg.payment.ucp`

> class `tool_gate` · `native` · package `mcpg-plugin-payment-ucp` · artifact `libmcpg_plugin_payment_ucp.so` · BUSL-1.1

Commerce gate that lets an MCP agent buy from UCP-compatible merchants. When a
purchasing tool is called, the plugin discovers the merchant from its
`/.well-known/ucp` profile, checks it advertises the capabilities the tool
requires, opens a checkout at the merchant's service endpoint, and hands the
agent the checkout state as an HTTP 402 challenge — releasing the tool only once
the merchant reports the checkout completed. Reach for it when a tool represents
a real purchase and you want the merchant's own discovery document to drive
endpoint and transport selection, under an origin allowlist you control.

## What it does
- Gates only the tools named in its `tools` map, and only on the tool surface.
  Everything else passes through untouched.
- Discovers the merchant at `<merchant_url>/.well-known/ucp`, caching the profile
  for `discovery_cache_ttl_ms`, and refuses to proceed unless the profile
  advertises every capability the tool lists.
- Resolves the service endpoint from the profile's `dev.ucp.shopping` service,
  preferring the tool's `transport` and falling back to the first entry offered.
- **Constrains that endpoint before sending anything to it**: it must be `https`
  and share an origin with the configured `merchant_url`, or match an origin the
  operator listed explicitly.
- Opens the checkout by POSTing to `<endpoint>/create_checkout`, then answers
  `Challenge` — HTTP 402, JSON-RPC code `-33050` — carrying the merchant's
  checkout state and any payment instruments it offered.
- Completes at `<endpoint>/complete_checkout` once the agent supplies
  `_meta["ucp/payment_instrument"]`, and grants the call **only** when the
  merchant reports status `completed`, returning the merchant's order object
  under `ucp/order`.
- Binds each checkout to the principal that created it, so one caller cannot
  address another's checkout by guessing its id.
- Declares the `network_outbound` capability, consumed by discovery and checkout.

## Configuration
Loaded from the flat top-level `plugins:` list. The `config:` block has two
halves: a `config` sub-object for protocol-wide settings, and a `tools` map whose
keys are the tool names to put behind checkout. With no `tools` entries the
plugin loads disabled and allows every call.

```yaml
plugins:
  - id: dev.mcpg.payment.ucp
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_payment_ucp.so }
    # or, platform-agnostic — the gateway resolves the artifact for its own
    # os/arch/libc at boot:
    # source: { oci: ghcr.io/mcpg-dev/source-code/plugins/payment-ucp:protocol-1 }
    granted_capabilities: [network_outbound]   # required — discovery + checkout
    config:
      config:
        platform_profile_url: https://gateway.example/.well-known/ucp
        session_ttl_ms: 3600000          # 1 hour
        discovery_cache_ttl_ms: 3600000  # 1 hour
        http_timeout_ms: 30000
      tools:
        store.checkout:
          merchant_url: https://merchant.example      # required
          capabilities: ["dev.ucp.shopping.checkout"]
          transport: rest                             # mcp | rest
          allowed_endpoint_origins:                   # empty = same-origin only
            - https://api.merchant.example
          auth_token: ${env.UCP_MERCHANT_TOKEN}
```

Protocol settings, under `config.config`:

| Field | Type | Default | Description |
|---|---|---|---|
| `platform_profile_url` | string | `""` | Advertised to merchants as `meta["ucp-agent"].profile` on checkout creation. |
| `session_ttl_ms` | integer | `3600` | Checkout lifetime in milliseconds. Past it the checkout is dropped and the call denied with HTTP 410. Set this to the real window you want to give an agent — the default is under four seconds. |
| `discovery_cache_ttl_ms` | integer | `3600` | How long a fetched merchant profile is reused, in milliseconds. |
| `http_timeout_ms` | integer | `30` | Merchant request timeout, in milliseconds. Set this to a realistic value for your merchant — the default is 30 milliseconds. |
| `default_transport` | string | `"rest"` | Accepted by the schema. Endpoint resolution reads the per-tool `transport`. |

Per-tool settings, under `config.tools.<tool name>`:

| Field | Type | Default | Description |
|---|---|---|---|
| `merchant_url` | string | required | Merchant base URL; discovery reads `<merchant_url>/.well-known/ucp`. Must be non-empty. |
| `allowed_endpoint_origins` | string[] | `[]` | Extra origins the discovery document may name as its service endpoint. Empty means same-origin as `merchant_url` only. |
| `capabilities` | string[] | `["dev.ucp.shopping.checkout"]` | Capabilities the merchant profile must advertise, or checkout creation fails. |
| `transport` | string | `"rest"` | Preferred service transport, `"mcp"` or `"rest"`. If the profile lists no entry with that transport, its first entry is used. |
| `auth_token` | string | unset | Bearer token sent on merchant calls. Omit for a merchant that needs none. |
| `enable_ap2` | bool | `false` | Accepted by the schema; AP2 mandate signing is not performed by the plugin. |
| `default_checkout_args` | JSON | unset | Seeds the checkout body's `checkout` object. Non-empty tool arguments are merged in at `checkout.tool_arguments`. |

Unknown fields are rejected, at the wire level and inside both nested blocks.

The plugin declares the `network_outbound` capability, so the entry has to grant
it: a packaged load (`source.path` pointing at a `.zip`, or `source.oci`) is
refused at boot when `granted_capabilities` does not list it.

**Credential handling.** Write `auth_token` as a `${env.VAR}` interpolation or an
`env://VAR` / `file://path` secret reference. The gateway resolves both to a
literal value at config load, before the plugin sees the config, so the merchant
secret never has to live in the plugin's YAML.

## Operations
The agent drives the whole checkout through MCP `_meta`:

| Key | Direction | Meaning |
|---|---|---|
| `ucp/checkout_session` | client → gateway | The merchant checkout id to resume. Absent means "open a new one". |
| `ucp/payment_instrument` | client → gateway | The instrument to complete the checkout with, forwarded as `checkout.payment.instruments[0]`. |
| `ucp/order` | gateway → client | The merchant's order object, returned on the allowed call. |

A typical exchange is: call the tool with no checkout, receive a 402 with the
merchant's checkout state and offered instruments; call again with
`ucp/checkout_session` plus `ucp/payment_instrument`; receive either the allowed
tool result with `ucp/order`, or another 402 if the merchant has not settled.

## Security
**The service endpoint is untrusted input.** It arrives inside the merchant's
discovery document and is where the operator's merchant credential and the
caller's payment instrument get POSTed. Before anything is sent, the endpoint
must be `https` and its `scheme://host[:port]` must equal the configured
`merchant_url`'s origin or appear in `allowed_endpoint_origins`. An empty
allowlist means same-origin only, which is the fail-closed default; internal
addresses and attacker-chosen collectors are refused outright.

**Redirects are disabled.** The HTTP client follows no redirects, because the
origin check runs before the credential is attached and a redirect would deliver
it to a host that check never saw.

**Settlement is proved, not assumed.** A non-error HTTP response from the
merchant is not treated as payment. Only status `completed` grants the call —
`incomplete`, `requires_action`, `ready_for_complete`, `complete_in_progress`,
`canceled`, and a missing status all re-challenge. The order metadata is built
from the merchant's own `order` object; when it is absent the gate emits a bare
checkout reference rather than inventing a success receipt.

**Checkouts are owned.** Each checkout is stamped with an ownership key derived
from the caller's subject and issuer, falling back to the MCP session id for
anonymous callers. A caller presenting someone else's checkout id is refused with
a "not found" shaped denial, so checkout existence is not leaked to a non-owner.

**Responses from private addresses are refused.** Discovery and checkout
responses both pass a DNS-rebinding check that rejects a reply arriving from a
private or loopback address.

**Config failure modes are asymmetric — know which one you are in.** Malformed
JSON, an unknown key, or a `tools` entry that omits `merchant_url` refuses the
plugin at boot, so a typo cannot open the gate. An empty or absent `config:`
block, a block with no top-level `config`, and
a structurally valid block that fails validation (an empty `merchant_url`) all
load the plugin **disabled** — which allows every call. Treat a startup log line
naming a disabled payment gate as a production incident, and assert on it in
deployment checks.

**Checkouts live in the process.** Checkout state and the discovery cache are
held in the plugin instance, so an agent must return to the same gateway replica
to complete a checkout, and a restart invalidates open ones.

**Error codes stay clear of the MCP reserved range.** `-33050` (checkout
required — also the code on the re-challenge after an unsettled or failed
completion), `-33051` (checkout creation failed), and `-33052` (checkout missing
or expired) sit outside `-32099..=-32000`.

## Observability
- `mcpg_payment_ucp_evaluations_total{outcome}` — `allow`, `deny`, `challenge`,
  or `pending_approval`.
- `mcpg_payment_ucp_evaluate_ms` — pre-dispatch evaluation latency.

Each evaluation opens a `ucp_payment_evaluate_pre` tracing span tagged with the
plugin id and tool name. Checkout creation and completion log at INFO; ownership
refusals, unsettled completions, and failed merchant calls log at WARN.

## Build
The `cdylib-export` feature gates the `mcpg_plugin_register` export. It is on by
default for a standalone build and switched off when the crate is linked as a
path dependency alongside other plugins, since several `mcpg_plugin_register`
symbols collide at link time:

```bash
cargo build -p mcpg-plugin-payment-ucp --features cdylib-export --release   # → target/release/libmcpg_plugin_payment_ucp.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, loading, and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Sibling payment gates: `libs/plugins/payment/acp`, `libs/plugins/payment/x402`,
  `libs/plugins/payment/mpp`
- Licence: BUSL-1.1 — see [`LICENSE`](./LICENSE) for the Additional Use Grant
  that governs production use.
