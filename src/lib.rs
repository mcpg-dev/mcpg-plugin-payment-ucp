//! # mcpg-plugin-payment-ucp
//!
//! Universal Commerce Protocol (UCP) plugin for the MCPG gateway.
//!
//! Enables AI agents to purchase products from UCP-compatible merchants
//! (Google/Shopify ecosystem) through the gateway. The plugin acts as a
//! commerce facilitator: it discovers merchant capabilities, manages
//! checkout sessions, and coordinates payment instrument exchange.
//!
//! ## How it works
//!
//! 1. First tool call (no session) → discover merchant, create checkout → Challenge
//! 2. Agent returns with session + payment instrument → complete checkout → Allow
//! 3. Multi-step updates supported (address, shipping selection)
//!
//! ## _meta keys
//!
//! - `ucp/checkout_session` — session ID (client → gateway)
//! - `ucp/payment_instrument` — payment data (client → gateway)
//! - `ucp/fulfillment` — address/shipping data (client → gateway)
//! - `ucp/order` — order data (gateway → client)

pub mod checkout;
pub mod discovery;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use mcpg_plugin_protocol::{
    GateDecision, PluginClass, PluginContext, PluginManifest, ToolGatePlugin, async_trait,
    payment::{PaymentAwarePlugin, PaymentCapability, PaymentCategory, PaymentProtocol},
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

const PLUGIN_ID: &str = "dev.mcpg.payment.ucp";

/// Stable ownership key for a checkout session. An authenticated caller
/// is keyed by subject (+issuer); an anonymous caller falls back to its
/// MCP session id so a different connection cannot address its session.
/// Used to prevent cross-principal checkout IDOR.
fn checkout_owner_key(ctx: &PluginContext) -> String {
    match ctx.identity.subject_id.as_deref() {
        Some(s) if !s.is_empty() => {
            format!("sub:{}|{}", s, ctx.identity.issuer.as_deref().unwrap_or(""))
        }
        _ => format!("sess:{}", ctx.session_id.as_deref().unwrap_or("anon")),
    }
}

use crate::checkout::{SessionTransport, UcpCheckoutSession};
use crate::discovery::{CachedMerchantProfile, ResolvedTransport};

// ---------------------------------------------------------------------------
// Config types (operator-facing)
// ---------------------------------------------------------------------------

/// Top-level UCP protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UcpProtocolConfig {
    /// Platform profile URL advertised to merchants.
    #[serde(default)]
    pub platform_profile_url: String,

    /// Session TTL in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_ms: u64,

    /// Discovery cache TTL in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_discovery_cache_ttl")]
    pub discovery_cache_ttl_ms: u64,

    /// Preferred transport for merchant communication.
    /// "mcp" or "rest". Default: "rest".
    #[serde(default = "default_transport")]
    pub default_transport: String,

    /// HTTP timeout in seconds. Default: 30.
    #[serde(default = "default_http_timeout")]
    pub http_timeout_ms: u64,
}

fn default_session_ttl() -> u64 {
    3600
}
fn default_discovery_cache_ttl() -> u64 {
    3600
}
fn default_transport() -> String {
    "rest".into()
}
fn default_http_timeout() -> u64 {
    30
}

/// Per-tool UCP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UcpToolConfig {
    /// Merchant's base URL (used for discovery).
    pub merchant_url: String,

    /// Origins the merchant's discovery document is permitted to name as
    /// its service endpoint, in addition to `merchant_url`'s own origin.
    ///
    /// The endpoint arrives in a remote, untrusted document and is where
    /// the operator's merchant credential and the caller's payment
    /// instrument get POSTed, so it is constrained to origins the operator
    /// chose. Empty means same-origin as `merchant_url` only.
    #[serde(default)]
    pub allowed_endpoint_origins: Vec<String>,

    /// Required UCP capabilities.
    #[serde(default = "default_capabilities")]
    pub capabilities: Vec<String>,

    /// Preferred transport: "mcp" or "rest".
    #[serde(default = "default_transport")]
    pub transport: String,

    /// Whether to enable AP2 mandate signing.
    #[serde(default)]
    pub enable_ap2: bool,

    /// Bearer token value used to authenticate to the merchant. Optional —
    /// when set, every merchant call (create / complete checkout) carries
    /// `Authorization: Bearer <token>`. Authenticating the channel keeps an
    /// unauthenticated party from impersonating the merchant's settlement
    /// response. The operator populates this from `${env.X}` / `cred://…`,
    /// which the gateway substitutes to the literal token at config load;
    /// the plugin reads it directly. Mirrors the ACP plugin's `auth_token`.
    #[serde(default)]
    pub auth_token: Option<String>,

    /// Static arguments to pass to checkout (e.g., pre-selected items).
    #[serde(default)]
    pub default_checkout_args: Option<Value>,
}

fn default_capabilities() -> Vec<String> {
    vec!["dev.ucp.shopping.checkout".into()]
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

// Payment codes live outside the MCP-reserved JSON-RPC range
// (-32000..-32099) to avoid collision with future spec assignments.

/// JSON-RPC error code for UCP checkout required.
const UCP_CHECKOUT_REQUIRED_CODE: i32 = -33050;
/// JSON-RPC error code for UCP checkout creation failure.
const UCP_CHECKOUT_CREATE_FAILED_CODE: i32 = -33051;
/// JSON-RPC error code for UCP checkout completion failure.
const UCP_CHECKOUT_COMPLETE_FAILED_CODE: i32 = -33052;

/// UCP Commerce Plugin.
///
/// Manages checkout sessions with UCP-compatible merchants, handling
/// discovery, session lifecycle, and payment coordination.
pub struct UcpCommercePlugin {
    manifest: PluginManifest,
    enabled: bool,

    /// Tools configured for UCP commerce, keyed by tool name.
    tool_configs: BTreeMap<String, UcpToolConfig>,

    /// Active checkout sessions. Key: session_id.
    sessions: DashMap<String, UcpCheckoutSession>,

    /// Cached merchant discovery profiles. Key: merchant base URL.
    merchant_profiles: DashMap<String, CachedMerchantProfile>,

    /// HTTP client for merchant API calls.
    http_client: reqwest::blocking::Client,

    /// Platform profile URL.
    platform_profile_url: String,

    /// Session TTL for cleanup.
    session_ttl: Duration,

    /// Discovery cache TTL.
    discovery_cache_ttl: Duration,

    /// Default preferred transport (resolved into per-tool config at registration).
    _default_transport: String,
}

impl std::fmt::Debug for UcpCommercePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UcpCommercePlugin")
            .field("enabled", &self.enabled)
            .field("tool_configs", &self.tool_configs)
            .finish()
    }
}

impl UcpCommercePlugin {
    /// Create a disabled (no-op) plugin.
    pub fn disabled() -> Self {
        Self {
            manifest: Self::make_manifest(),
            enabled: false,
            tool_configs: BTreeMap::new(),
            sessions: DashMap::new(),
            merchant_profiles: DashMap::new(),
            http_client: reqwest::blocking::Client::new(),
            platform_profile_url: String::new(),
            session_ttl: Duration::from_secs(3600),
            discovery_cache_ttl: Duration::from_secs(3600),
            _default_transport: "rest".into(),
        }
    }

    /// Create from protocol config and per-tool configs.
    pub fn from_config(
        config: &UcpProtocolConfig,
        tool_configs: BTreeMap<String, UcpToolConfig>,
    ) -> Result<Self> {
        if tool_configs.is_empty() {
            return Ok(Self::disabled());
        }

        // Validate each tool has a merchant_url
        for (name, cfg) in &tool_configs {
            if cfg.merchant_url.is_empty() {
                return Err(anyhow::anyhow!(
                    "UCP: merchant_url is required for tool '{}'",
                    name,
                ));
            }
        }

        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(config.http_timeout_ms))
            // The endpoint is origin-checked before the credential is
            // attached; following a redirect would deliver it to a host that
            // check never saw.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        Ok(Self {
            manifest: Self::make_manifest(),
            enabled: true,
            tool_configs,
            sessions: DashMap::new(),
            merchant_profiles: DashMap::new(),
            http_client,
            platform_profile_url: config.platform_profile_url.clone(),
            session_ttl: Duration::from_millis(config.session_ttl_ms),
            discovery_cache_ttl: Duration::from_millis(config.discovery_cache_ttl_ms),
            _default_transport: config.default_transport.clone(),
        })
    }

    fn make_manifest() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "Universal Commerce Protocol (UCP)".into(),
            plugin_class: PluginClass::ToolGate,
            protocol_version: "1.0".into(),
            // Discovery + checkout call merchant URLs.
            license: None,
            required_capabilities: Vec::new(), // host-derived from declare_plugin! capabilities (typed)
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    /// SDK macro factory: parses operator config JSON. Layout:
    /// `{ "config": ProtocolConfig, "tools": { name: ToolConfig } }`.
    pub fn from_config_json(config_json: &str) -> Self {
        // Default: empty `config`, no tools → resolves to `disabled()`
        // below, matching the historical empty-config behavior.
        #[derive(serde::Deserialize, Default)]
        #[serde(deny_unknown_fields)]
        struct WireConfig {
            #[serde(default)]
            config: Option<UcpProtocolConfig>,
            #[serde(default)]
            tools: BTreeMap<String, UcpToolConfig>,
        }
        // Fail CLOSED on a present-but-malformed operator `config:` block:
        // a payment gate must refuse to boot rather than silently degrade
        // to defaults. An empty / absent block still yields Default.
        let wire: WireConfig = mcpg_plugin_sdk::fail_closed_config!(config_json, WireConfig);
        match wire.config {
            Some(cfg) => Self::from_config(&cfg, wire.tools).unwrap_or_else(|err| {
                tracing::error!(
                    error = %err,
                    "payment-ucp: config compile failed; loading as DISABLED"
                );
                Self::disabled()
            }),
            None => {
                tracing::warn!(
                    "payment-ucp: config JSON missing top-level `config`; loading as DISABLED"
                );
                Self::disabled()
            }
        }
    }

    /// Resolve the merchant bearer token for a tool, if one is configured.
    /// Returns `Ok(None)` when no (or an empty) `auth_token` is set (public
    /// merchant); a non-empty value authenticates every merchant call.
    fn auth_token(&self, tool_config: &UcpToolConfig) -> Result<Option<String>> {
        match tool_config.auth_token.as_deref() {
            Some(tok) if !tok.is_empty() => Ok(Some(tok.to_owned())),
            _ => Ok(None),
        }
    }

    /// Discover merchant and create a checkout session.
    fn create_checkout_session(
        &self,
        tool_name: &str,
        tool_config: &UcpToolConfig,
        auth: Option<&str>,
        arguments: &Value,
    ) -> Result<UcpCheckoutSession> {
        // 1. Discover merchant
        let profile = self.discover_merchant(&tool_config.merchant_url)?;

        // 2. Validate capabilities
        discovery::validate_capabilities(&profile, &tool_config.capabilities)?;

        // 3. Resolve endpoint
        let transport = &tool_config.transport;
        let resolved = discovery::resolve_endpoint(&profile, "dev.ucp.shopping", transport)?;

        let endpoint_url = match &resolved {
            ResolvedTransport::Mcp { endpoint } => endpoint.clone(),
            ResolvedTransport::Rest { endpoint } => endpoint.clone(),
        };
        // The endpoint came out of the merchant's discovery document, and the
        // credential is attached below — constrain it before anything is sent.
        discovery::enforce_endpoint_origin(
            &endpoint_url,
            &tool_config.merchant_url,
            &tool_config.allowed_endpoint_origins,
        )?;

        // 4. Create checkout request
        let checkout_body = self.build_create_checkout_body(tool_config, arguments);

        // 5. Call merchant
        let mut req = self
            .http_client
            .post(format!(
                "{}/create_checkout",
                endpoint_url.trim_end_matches('/')
            ))
            .header("Content-Type", "application/json")
            .json(&checkout_body);
        if let Some(token) = auth {
            req = req.bearer_auth(token);
        }
        let response = req
            .send()
            .map_err(|e| anyhow::anyhow!("UCP merchant request failed: {}", e))?;

        // Security: DNS rebinding guard.
        mcpg_plugin_protocol::security::check_response_remote_addr(response.remote_addr(), false)
            .map_err(|e| anyhow::anyhow!("UCP merchant SSRF blocked: {e}"))?;

        let status = response.status().as_u16();
        let body: Value = response
            .json()
            .map_err(|e| anyhow::anyhow!("UCP merchant response parse error: {}", e))?;

        if status >= 400 {
            return Err(anyhow::anyhow!(
                "UCP merchant create_checkout returned HTTP {}: {}",
                status,
                body,
            ));
        }

        info!(
            tool_name = %tool_name,
            merchant = %tool_config.merchant_url,
            session_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
            "UCP checkout session created"
        );

        let session_transport = match &resolved {
            ResolvedTransport::Mcp { endpoint } => SessionTransport::Mcp {
                endpoint: endpoint.clone(),
            },
            ResolvedTransport::Rest { endpoint } => SessionTransport::Rest {
                endpoint: endpoint.clone(),
            },
        };

        UcpCheckoutSession::from_response(
            body,
            tool_config.merchant_url.clone(),
            endpoint_url,
            session_transport,
        )
        .ok_or_else(|| anyhow::anyhow!("UCP merchant response missing session ID"))
    }

    /// Discover a merchant profile (with caching).
    fn discover_merchant(&self, merchant_url: &str) -> Result<discovery::MerchantProfile> {
        // Check cache
        if let Some(cached) = self.merchant_profiles.get(merchant_url)
            && !cached.is_expired()
        {
            return Ok(cached.profile.clone());
        }

        // Fetch
        let profile = discovery::fetch_merchant_profile(&self.http_client, merchant_url)?;

        // Cache
        let entry = discovery::create_cache_entry(profile.clone(), self.discovery_cache_ttl);
        self.merchant_profiles
            .insert(merchant_url.to_owned(), entry);

        Ok(profile)
    }

    /// Complete a checkout session with payment instrument.
    fn complete_checkout(
        &self,
        session: &mut UcpCheckoutSession,
        auth: Option<&str>,
        payment_instrument: &Value,
    ) -> Result<Value> {
        let endpoint = match &session.transport {
            SessionTransport::Mcp { endpoint } | SessionTransport::Rest { endpoint } => {
                endpoint.clone()
            }
        };

        let complete_body = serde_json::json!({
            "id": session.session_id,
            "checkout": {
                "payment": {
                    "instruments": [payment_instrument]
                }
            }
        });

        let mut req = self
            .http_client
            .post(format!(
                "{}/complete_checkout",
                endpoint.trim_end_matches('/')
            ))
            .header("Content-Type", "application/json")
            .json(&complete_body);
        if let Some(token) = auth {
            req = req.bearer_auth(token);
        }
        let response = req
            .send()
            .map_err(|e| anyhow::anyhow!("UCP complete_checkout failed: {}", e))?;

        // Security: DNS rebinding guard.
        mcpg_plugin_protocol::security::check_response_remote_addr(response.remote_addr(), false)
            .map_err(|e| anyhow::anyhow!("UCP merchant SSRF blocked: {e}"))?;

        let status = response.status().as_u16();
        let body: Value = response
            .json()
            .map_err(|e| anyhow::anyhow!("UCP complete response parse error: {}", e))?;

        if status >= 400 {
            return Err(anyhow::anyhow!(
                "UCP complete_checkout returned HTTP {}: {}",
                status,
                body,
            ));
        }

        session.update_from_response(body.clone());

        info!(
            session_id = %session.session_id,
            status = ?session.status,
            "UCP checkout completed"
        );

        Ok(body)
    }

    /// Build the create_checkout request body.
    fn build_create_checkout_body(&self, tool_config: &UcpToolConfig, arguments: &Value) -> Value {
        let mut body = serde_json::json!({
            "meta": {
                "ucp-agent": {
                    "profile": self.platform_profile_url
                }
            },
            "checkout": {}
        });

        // Merge default checkout args if any
        if let Some(defaults) = &tool_config.default_checkout_args {
            body["checkout"] = defaults.clone();
        }

        // Pass tool arguments as line items context
        if let Some(args_obj) = arguments.as_object()
            && !args_obj.is_empty()
        {
            body["checkout"]["tool_arguments"] = arguments.clone();
        }

        body
    }
}

// ---------------------------------------------------------------------------
// SyncToolGate (cdylib path) + async ToolGatePlugin (gateway path-dep)
// ---------------------------------------------------------------------------

impl SyncToolGate for UcpCommercePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from the UCP commerce gate
        // attribute back to dev.mcpg.payment.ucp.
        let _span = tracing::info_span!(
            "ucp_payment_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = std::time::Instant::now();
        let decision = self.evaluate_pre_inner(ctx, arguments, meta, config);
        let outcome = match &decision {
            GateDecision::Allow { .. } => "allow",
            GateDecision::Deny { .. } => "deny",
            GateDecision::Challenge { .. } => "challenge",
            GateDecision::PendingApproval { .. } => "pending_approval",
        };
        metrics::counter!(
            "mcpg_payment_ucp_evaluations_total",
            "outcome" => outcome,
        )
        .increment(1);
        metrics::histogram!("mcpg_payment_ucp_evaluate_ms")
            .record(started.elapsed().as_millis() as f64);
        decision
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        // No post-dispatch logic — checkout completes during pre.
        GateDecision::allow()
    }
}

impl UcpCommercePlugin {
    fn evaluate_pre_inner(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if !self.enabled {
            return GateDecision::allow();
        }
        // Payment gating applies to tool calls only — non-tool surfaces
        // are never charged.
        if ctx.surface != "tool" {
            return GateDecision::allow();
        }

        let tool_config = match self.tool_configs.get(&ctx.tool_name) {
            Some(cfg) => cfg,
            None => return GateDecision::allow(),
        };

        // Resolve the (optional) merchant bearer token up front. A token
        // resolution failure fails closed rather than calling the merchant
        // unauthenticated.
        let auth = match self.auth_token(tool_config) {
            Ok(token) => token,
            Err(e) => {
                warn!(
                    tool_name = %ctx.tool_name,
                    error = %e,
                    "UCP merchant auth token unavailable"
                );
                return GateDecision::Deny {
                    http_status: 500,
                    code: UCP_CHECKOUT_CREATE_FAILED_CODE,
                    message: format!("UCP merchant authentication unavailable: {}", e),
                    error_data: None,
                };
            }
        };

        // Check for existing checkout session reference in _meta
        let session_ref = meta
            .and_then(|m| m.get("ucp/checkout_session"))
            .and_then(|v| v.as_str());

        match session_ref {
            None => {
                // No session — create checkout
                match self.create_checkout_session(
                    &ctx.tool_name,
                    tool_config,
                    auth.as_deref(),
                    arguments,
                ) {
                    Ok(mut session) => {
                        // Stamp the creating principal so only they can
                        // address this session later (IDOR guard).
                        session.owner = checkout_owner_key(ctx);
                        let challenge_data = session.build_challenge_data();
                        let session_id = session.session_id.clone();
                        self.sessions.insert(session_id, session);

                        GateDecision::Challenge {
                            http_status: 402,
                            code: UCP_CHECKOUT_REQUIRED_CODE,
                            message: format!("UCP checkout required for tool '{}'", ctx.tool_name,),
                            challenge_data,
                        }
                    }
                    Err(e) => {
                        warn!(
                            tool_name = %ctx.tool_name,
                            error = %e,
                            "UCP checkout session creation failed"
                        );
                        GateDecision::Deny {
                            http_status: 500,
                            code: UCP_CHECKOUT_CREATE_FAILED_CODE,
                            message: format!("UCP checkout creation failed: {}", e),
                            error_data: None,
                        }
                    }
                }
            }
            Some(session_id) => {
                // Session exists — look it up
                let mut session_entry = match self.sessions.get_mut(session_id) {
                    Some(entry) => entry,
                    None => {
                        return GateDecision::Deny {
                            http_status: 404,
                            code: UCP_CHECKOUT_COMPLETE_FAILED_CODE,
                            message: format!(
                                "UCP checkout session '{}' not found or expired",
                                session_id,
                            ),
                            error_data: None,
                        };
                    }
                };

                // Ownership check: a different principal must not be
                // able to read or complete someone else's checkout by
                // guessing its session id. Respond as "not found" so the
                // session's existence isn't leaked to a non-owner.
                if session_entry.owner != checkout_owner_key(ctx) {
                    drop(session_entry);
                    warn!(
                        session_id = %session_id,
                        tool_name = %ctx.tool_name,
                        "UCP checkout session access denied: caller is not the owner"
                    );
                    return GateDecision::Deny {
                        http_status: 404,
                        code: UCP_CHECKOUT_COMPLETE_FAILED_CODE,
                        message: format!(
                            "UCP checkout session '{}' not found or expired",
                            session_id,
                        ),
                        error_data: None,
                    };
                }

                // Check expiry
                if session_entry.is_expired(self.session_ttl) {
                    drop(session_entry);
                    self.sessions.remove(session_id);
                    return GateDecision::Deny {
                        http_status: 410,
                        code: UCP_CHECKOUT_COMPLETE_FAILED_CODE,
                        message: format!("UCP checkout session '{}' expired", session_id),
                        error_data: None,
                    };
                }

                // Check for payment instrument
                let payment_instrument = meta.and_then(|m| m.get("ucp/payment_instrument"));

                match payment_instrument {
                    Some(instrument) => {
                        // Complete checkout
                        match self.complete_checkout(
                            &mut session_entry,
                            auth.as_deref(),
                            instrument,
                        ) {
                            Ok(_body) => {
                                // SECURITY (payment bypass): a non-error HTTP
                                // response is NOT proof of settlement. Only
                                // grant the tool call once the merchant has
                                // reported the checkout `completed`. Any other
                                // status — incomplete / requires_action /
                                // ready / complete_in_progress, or a missing
                                // status (which parses as Incomplete) — must
                                // re-challenge, never Allow. Granting on any
                                // 2xx was the MPP-class payment bypass.
                                if !session_entry.is_settled() {
                                    let observed = session_entry.status.clone();
                                    let challenge_data = session_entry.build_challenge_data();
                                    warn!(
                                        session_id = %session_id,
                                        status = ?observed,
                                        "UCP completion did not reach `completed`; withholding Allow"
                                    );
                                    return GateDecision::Challenge {
                                        http_status: 402,
                                        code: UCP_CHECKOUT_REQUIRED_CODE,
                                        message: format!(
                                            "UCP checkout '{}' not settled (status {:?}); \
                                             payment not confirmed",
                                            session_id, observed,
                                        ),
                                        challenge_data,
                                    };
                                }

                                let order_meta = session_entry.build_order_meta();
                                // Clean up session
                                let sid = session_id.to_owned();
                                drop(session_entry);
                                self.sessions.remove(&sid);

                                GateDecision::allow_with_metadata(order_meta)
                            }
                            Err(e) => {
                                warn!(
                                    session_id = %session_id,
                                    error = %e,
                                    "UCP checkout completion failed"
                                );
                                // Return as challenge so agent can retry
                                let challenge_data = session_entry.build_challenge_data();
                                GateDecision::Challenge {
                                    http_status: 402,
                                    code: UCP_CHECKOUT_REQUIRED_CODE,
                                    message: format!("UCP checkout completion failed: {}", e,),
                                    challenge_data,
                                }
                            }
                        }
                    }
                    None => {
                        // Session exists but no payment yet — check for updates
                        // (fulfillment, address, etc.) and re-challenge
                        let challenge_data = session_entry.build_challenge_data();
                        GateDecision::Challenge {
                            http_status: 402,
                            code: UCP_CHECKOUT_REQUIRED_CODE,
                            message: format!(
                                "UCP checkout session '{}' awaiting payment",
                                session_id,
                            ),
                            challenge_data,
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ToolGatePlugin for UcpCommercePlugin {
    fn manifest(&self) -> &PluginManifest {
        SyncToolGate::manifest(self)
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        SyncToolGate::evaluate_pre(self, ctx, arguments, meta, config)
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: UcpCommercePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| UcpCommercePlugin::from_config_json(cfg),
        }
    ],
}

// ---------------------------------------------------------------------------
// PaymentAwarePlugin implementation
// ---------------------------------------------------------------------------

impl PaymentAwarePlugin for UcpCommercePlugin {
    fn payment_capabilities(&self) -> Vec<PaymentCapability> {
        vec![PaymentCapability {
            protocol: PaymentProtocol::Ucp,
            methods: vec!["checkout".into()],
            supports_sessions: true,
            supports_commerce: true,
            meta_prefix: "ucp/".into(),
        }]
    }

    fn credential_meta_keys(&self) -> Vec<String> {
        vec![
            "ucp/checkout_session".into(),
            "ucp/payment_instrument".into(),
        ]
    }

    fn payment_category(&self) -> PaymentCategory {
        PaymentCategory::Commerce
    }

    fn configured_tools(&self) -> Vec<String> {
        self.tool_configs.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginClass;

    fn test_tool_configs() -> BTreeMap<String, UcpToolConfig> {
        let mut m = BTreeMap::new();
        m.insert(
            "buy_product".to_owned(),
            UcpToolConfig {
                merchant_url: "https://merchant.example.com".into(),
                allowed_endpoint_origins: Vec::new(),
                capabilities: vec!["dev.ucp.shopping.checkout".into()],
                transport: "rest".into(),
                enable_ap2: false,
                auth_token: None,
                default_checkout_args: None,
            },
        );
        m
    }

    fn test_ctx(tool_name: &str) -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: None,
            tool_name: tool_name.into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn disabled_plugin_allows() {
        let plugin = UcpCommercePlugin::disabled();
        let decision = plugin.evaluate_pre(
            &test_ctx("any"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn unconfigured_tool_allows() {
        let config = UcpProtocolConfig {
            platform_profile_url: "https://agent.example.com/.well-known/ucp".into(),
            session_ttl_ms: 3600,
            discovery_cache_ttl_ms: 3600,
            default_transport: "rest".into(),
            http_timeout_ms: 30,
        };
        let plugin = UcpCommercePlugin::from_config(&config, test_tool_configs()).unwrap();
        let decision = plugin.evaluate_pre(
            &test_ctx("free_tool"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn session_not_found_denied() {
        let config = UcpProtocolConfig {
            platform_profile_url: "".into(),
            session_ttl_ms: 3600,
            discovery_cache_ttl_ms: 3600,
            default_transport: "rest".into(),
            http_timeout_ms: 5,
        };
        let plugin = UcpCommercePlugin::from_config(&config, test_tool_configs()).unwrap();

        let meta = serde_json::json!({
            "ucp/checkout_session": "nonexistent_session"
        });
        let decision = plugin.evaluate_pre(
            &test_ctx("buy_product"),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );

        match decision {
            GateDecision::Deny { code, message, .. } => {
                assert_eq!(code, UCP_CHECKOUT_COMPLETE_FAILED_CODE);
                assert!(message.contains("not found"), "got: {message}");
            }
            other => panic!("expected Deny, got: {:?}", other),
        }
    }

    fn test_ctx_with_subject(tool_name: &str, subject: &str) -> PluginContext {
        let mut ctx = test_ctx(tool_name);
        ctx.identity.kind = "verified".into();
        ctx.identity.trust_level = "verified".into();
        ctx.identity.subject_id = Some(subject.into());
        ctx
    }

    /// Regression: a checkout session created by one principal
    /// must not be readable or completable by another who supplies the
    /// merchant session id. Non-owner gets an opaque "not found"; owner passes.
    #[test]
    fn checkout_session_idor_denied_for_non_owner() {
        let config = UcpProtocolConfig {
            platform_profile_url: "".into(),
            session_ttl_ms: 3_600_000,
            discovery_cache_ttl_ms: 3600,
            default_transport: "rest".into(),
            http_timeout_ms: 5,
        };
        let plugin = UcpCommercePlugin::from_config(&config, test_tool_configs()).unwrap();

        let alice = test_ctx_with_subject("buy_product", "alice");
        let mut session = crate::checkout::UcpCheckoutSession::from_response(
            serde_json::json!({ "id": "ucp_owned", "status": "ready_for_payment" }),
            "https://merchant.example.com".into(),
            "https://merchant.example.com/checkout".into(),
            crate::checkout::SessionTransport::Rest {
                endpoint: "https://merchant.example.com/checkout".into(),
            },
        )
        .unwrap();
        session.owner = checkout_owner_key(&alice);
        plugin.sessions.insert("ucp_owned".to_owned(), session);

        let meta = serde_json::json!({ "ucp/checkout_session": "ucp_owned" });

        // Bob (different principal) is denied as "not found".
        let bob = test_ctx_with_subject("buy_product", "bob");
        match plugin.evaluate_pre(
            &bob,
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        ) {
            GateDecision::Deny { code, message, .. } => {
                assert_eq!(code, UCP_CHECKOUT_COMPLETE_FAILED_CODE);
                assert!(message.contains("not found"), "got: {message}");
            }
            other => panic!("non-owner must be denied, got: {other:?}"),
        }
        assert!(plugin.sessions.contains_key("ucp_owned"));

        // Alice (owner) passes the ownership gate.
        match plugin.evaluate_pre(
            &alice,
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        ) {
            GateDecision::Challenge { code, .. } => assert_eq!(code, UCP_CHECKOUT_REQUIRED_CODE),
            other => panic!("owner must pass the ownership gate, got: {other:?}"),
        }
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = UcpCommercePlugin::disabled();
        let m = SyncToolGate::manifest(&plugin);
        assert_eq!(m.id, "dev.mcpg.payment.ucp");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
    }

    #[test]
    fn payment_aware_capabilities() {
        let plugin = UcpCommercePlugin::disabled();
        let caps = plugin.payment_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].protocol, PaymentProtocol::Ucp);
        assert!(caps[0].supports_sessions);
        assert!(caps[0].supports_commerce);
    }

    #[test]
    fn payment_aware_category() {
        let plugin = UcpCommercePlugin::disabled();
        assert_eq!(plugin.payment_category(), PaymentCategory::Commerce);
    }

    #[test]
    fn empty_tool_configs_creates_disabled() {
        let config = UcpProtocolConfig {
            platform_profile_url: "".into(),
            session_ttl_ms: 3600,
            discovery_cache_ttl_ms: 3600,
            default_transport: "rest".into(),
            http_timeout_ms: 30,
        };
        let plugin = UcpCommercePlugin::from_config(&config, BTreeMap::new()).unwrap();
        assert!(!plugin.enabled);
    }

    #[test]
    fn missing_merchant_url_rejected() {
        let config = UcpProtocolConfig {
            platform_profile_url: "".into(),
            session_ttl_ms: 3600,
            discovery_cache_ttl_ms: 3600,
            default_transport: "rest".into(),
            http_timeout_ms: 30,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "bad_tool".to_owned(),
            UcpToolConfig {
                merchant_url: "".into(),
                allowed_endpoint_origins: Vec::new(),
                capabilities: vec![],
                transport: "rest".into(),
                enable_ap2: false,
                auth_token: None,
                default_checkout_args: None,
            },
        );
        let err = UcpCommercePlugin::from_config(&config, tools).unwrap_err();
        assert!(err.to_string().contains("merchant_url"), "got: {err}");
    }

    /// Error codes must not collide with the MCP-reserved JSON-RPC range.
    #[test]
    fn ucp_codes_outside_mcp_reserved_range() {
        for code in [
            UCP_CHECKOUT_REQUIRED_CODE,
            UCP_CHECKOUT_CREATE_FAILED_CODE,
            UCP_CHECKOUT_COMPLETE_FAILED_CODE,
        ] {
            assert!(
                !(-32099..=-32000).contains(&code),
                "UCP error code {code} collides with MCP reserved range [-32099, -32000]"
            );
        }
    }

    /// An empty / absent operator `config:` block must not be a parse
    /// error: it opts out and yields the disabled (Default) plugin.
    #[test]
    fn empty_config_yields_disabled() {
        for empty in ["{}", "", "null", "   "] {
            let plugin = UcpCommercePlugin::from_config_json(empty);
            assert!(
                !plugin.enabled,
                "empty config {empty:?} should yield a disabled plugin"
            );
            assert!(plugin.tool_configs.is_empty());
        }
    }

    /// A present-but-malformed operator `config:` block must FAIL CLOSED:
    /// `from_config_json` panics rather than silently degrading to
    /// defaults. The cdylib `make` slot converts this panic into a boot
    /// rejection.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_fails_closed() {
        let _ = UcpCommercePlugin::from_config_json("not json");
    }

    /// A stray / typo'd key at the wire-config level must be a parse error
    /// (`deny_unknown_fields`) so the fail-closed parser refuses the plugin
    /// at boot rather than silently ignoring it. Security-critical payment
    /// config: a typo must NOT pass.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_top_level_key_fails_closed() {
        let _ = UcpCommercePlugin::from_config_json(r#"{ "config": {}, "toolz": {} }"#);
    }

    /// A stray / typo'd key inside the nested `config` (UcpProtocolConfig)
    /// block must likewise fail closed.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_protocol_config_key_fails_closed() {
        let _ = UcpCommercePlugin::from_config_json(
            r#"{ "config": { "session_ttl_ms": 1000, "bogus_key": 1 } }"#,
        );
    }

    /// A stray / typo'd key inside a per-tool (UcpToolConfig) block must
    /// also fail closed.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_tool_config_key_fails_closed() {
        let _ = UcpCommercePlugin::from_config_json(
            r#"{ "config": {}, "tools": { "buy": {
                "merchant_url": "https://m.example.com",
                "typo_field": true
            } } }"#,
        );
    }
}
