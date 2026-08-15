//! Merchant discovery for UCP — fetching and caching `/.well-known/ucp` profiles.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Merchant Profile types (mirrors UCP spec)
// ---------------------------------------------------------------------------

/// UCP merchant profile returned from `/.well-known/ucp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantProfile {
    /// Merchant display name.
    #[serde(default)]
    pub name: String,

    /// Merchant capabilities.
    #[serde(default)]
    pub capabilities: serde_json::Value,

    /// Service endpoints per capability.
    #[serde(default)]
    pub services: serde_json::Map<String, serde_json::Value>,
}

/// Endpoint entry in a merchant profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub transport: String,
    pub endpoint: String,
}

/// Cached merchant profile with TTL.
#[derive(Debug, Clone)]
pub struct CachedMerchantProfile {
    pub profile: MerchantProfile,
    pub expires_at: Instant,
}

impl CachedMerchantProfile {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

// ---------------------------------------------------------------------------
// Endpoint resolution
// ---------------------------------------------------------------------------

/// Resolved transport endpoint for a merchant.
#[derive(Debug, Clone)]
pub enum ResolvedTransport {
    Mcp { endpoint: String },
    Rest { endpoint: String },
}

/// The scheme+host+port of a URL, for origin comparison.
fn origin_of(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid UCP URL '{url}'"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("UCP URL '{url}' has no host"))?;
    Ok(match parsed.port() {
        Some(p) => format!("{}://{}:{}", parsed.scheme(), host.to_ascii_lowercase(), p),
        None => format!("{}://{}", parsed.scheme(), host.to_ascii_lowercase()),
    })
}

/// Constrain a discovery-supplied service endpoint to an operator-chosen
/// origin.
///
/// The endpoint is read out of the merchant's `/.well-known/ucp` document —
/// remote, untrusted data — and is the address the operator's merchant
/// credential and the caller's payment instrument are POSTed to. Anyone who
/// can serve or spoof that document would otherwise choose where those
/// secrets go, including an internal address. The endpoint must therefore
/// share an origin with the operator-configured `merchant_url`, or match an
/// origin the operator listed explicitly; an empty list means same-origin
/// only, which is the fail-closed default.
pub fn enforce_endpoint_origin(
    endpoint: &str,
    merchant_url: &str,
    allowed_origins: &[String],
) -> Result<()> {
    let endpoint_origin = origin_of(endpoint)?;
    if !endpoint.starts_with("https://") {
        return Err(anyhow::anyhow!("UCP endpoint '{endpoint}' must use https"));
    }
    if endpoint_origin == origin_of(merchant_url)? {
        return Ok(());
    }
    for allowed in allowed_origins {
        if origin_of(allowed)
            .map(|o| o == endpoint_origin)
            .unwrap_or(false)
        {
            return Ok(());
        }
    }
    Err(anyhow::anyhow!(
        "UCP endpoint origin '{endpoint_origin}' is neither the merchant's own origin nor in \
         allowed_endpoint_origins; refusing to send merchant credentials there"
    ))
}

/// Resolve an endpoint from a merchant profile for a given service.
///
/// The returned endpoint is merchant-supplied and NOT yet trusted — pass it
/// through [`enforce_endpoint_origin`] before sending anything to it.
pub fn resolve_endpoint(
    profile: &MerchantProfile,
    service_key: &str,
    preferred_transport: &str,
) -> Result<ResolvedTransport> {
    let service = profile
        .services
        .get(service_key)
        .ok_or_else(|| anyhow::anyhow!("merchant has no '{}' service", service_key))?;

    let entries: Vec<ServiceEndpoint> = match service {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|e| serde_json::from_value(e.clone()).ok())
            .collect(),
        serde_json::Value::Object(_) => serde_json::from_value::<ServiceEndpoint>(service.clone())
            .map(|e| vec![e])
            .unwrap_or_default(),
        _ => vec![],
    };

    // Try preferred transport first
    for entry in &entries {
        if entry.transport == preferred_transport {
            return Ok(match preferred_transport {
                "mcp" => ResolvedTransport::Mcp {
                    endpoint: entry.endpoint.clone(),
                },
                _ => ResolvedTransport::Rest {
                    endpoint: entry.endpoint.clone(),
                },
            });
        }
    }

    // Fall back to the first available entry (regardless of transport).
    if let Some(entry) = entries.first() {
        return Ok(match entry.transport.as_str() {
            "mcp" => ResolvedTransport::Mcp {
                endpoint: entry.endpoint.clone(),
            },
            _ => ResolvedTransport::Rest {
                endpoint: entry.endpoint.clone(),
            },
        });
    }

    Err(anyhow::anyhow!(
        "no compatible transport found for merchant service '{}'",
        service_key,
    ))
}

// ---------------------------------------------------------------------------
// Discovery fetching
// ---------------------------------------------------------------------------

/// Fetch and parse a merchant's UCP discovery profile.
pub fn fetch_merchant_profile(
    http_client: &reqwest::blocking::Client,
    merchant_url: &str,
) -> Result<MerchantProfile> {
    let profile_url = format!("{}/.well-known/ucp", merchant_url.trim_end_matches('/'));

    let response = http_client
        .get(&profile_url)
        .header("Accept", "application/json")
        .send()
        .context("UCP merchant discovery request failed")?;

    // Security: DNS rebinding guard on merchant discovery.
    mcpg_plugin_protocol::security::check_response_remote_addr(response.remote_addr(), false)
        .map_err(|e| anyhow::anyhow!("UCP discovery SSRF blocked: {e}"))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "UCP merchant discovery failed: HTTP {}",
            response.status(),
        ));
    }

    response
        .json::<MerchantProfile>()
        .context("UCP merchant profile parse error")
}

/// Validate that a merchant supports required capabilities.
pub fn validate_capabilities(profile: &MerchantProfile, required: &[String]) -> Result<()> {
    if let Some(caps) = profile.capabilities.as_object() {
        for req in required {
            if !caps.contains_key(req) {
                return Err(anyhow::anyhow!(
                    "merchant does not support required capability: {}",
                    req,
                ));
            }
        }
    } else if !required.is_empty() {
        return Err(anyhow::anyhow!(
            "merchant has no capabilities object but {} required",
            required.len(),
        ));
    }
    Ok(())
}

/// Create a cache entry with a given TTL.
pub fn create_cache_entry(profile: MerchantProfile, ttl: Duration) -> CachedMerchantProfile {
    CachedMerchantProfile {
        profile,
        expires_at: Instant::now() + ttl,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> MerchantProfile {
        serde_json::from_value(serde_json::json!({
            "name": "Test Merchant",
            "capabilities": {
                "dev.ucp.shopping.checkout": {}
            },
            "services": {
                "dev.ucp.shopping": [
                    { "transport": "rest", "endpoint": "https://merchant.example.com/api" },
                    { "transport": "mcp", "endpoint": "https://merchant.example.com/mcp" }
                ]
            }
        }))
        .unwrap()
    }

    /// The endpoint comes from the merchant's own discovery document, and
    /// the operator's merchant credential plus the caller's payment
    /// instrument are POSTed to it. Anyone able to serve or spoof that
    /// document would otherwise pick where those secrets land.
    #[test]
    fn endpoint_origin_is_constrained_to_the_operator_choice() {
        let merchant = "https://merchant.example.com";

        // Same origin as the configured merchant — allowed.
        enforce_endpoint_origin("https://merchant.example.com/checkout", merchant, &[]).unwrap();

        // Attacker-chosen collector, and an internal address — both refused.
        for hostile in [
            "https://collector.attacker.test",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.5:8080/admin",
        ] {
            let err = enforce_endpoint_origin(hostile, merchant, &[]).unwrap_err();
            assert!(err.to_string().contains("origin"), "{hostile}: {err}");
        }

        // Plaintext is refused even on the merchant's own host.
        assert!(enforce_endpoint_origin("http://merchant.example.com/x", merchant, &[]).is_err());

        // An operator-listed origin is accepted; an unlisted one is not.
        let allowed = vec!["https://api.merchant.example.com".to_owned()];
        enforce_endpoint_origin("https://api.merchant.example.com/v2", merchant, &allowed).unwrap();
        assert!(enforce_endpoint_origin("https://other.example.com", merchant, &allowed).is_err());
    }

    #[test]
    fn resolve_preferred_transport() {
        let profile = sample_profile();
        let endpoint = resolve_endpoint(&profile, "dev.ucp.shopping", "mcp").unwrap();
        match endpoint {
            ResolvedTransport::Mcp { endpoint } => {
                assert_eq!(endpoint, "https://merchant.example.com/mcp");
            }
            other => panic!("expected Mcp, got: {:?}", other),
        }
    }

    #[test]
    fn resolve_fallback_transport() {
        let profile = sample_profile();
        let endpoint = resolve_endpoint(&profile, "dev.ucp.shopping", "grpc").unwrap();
        match endpoint {
            ResolvedTransport::Rest { endpoint } => {
                assert_eq!(endpoint, "https://merchant.example.com/api");
            }
            other => panic!("expected Rest fallback, got: {:?}", other),
        }
    }

    #[test]
    fn resolve_missing_service_errors() {
        let profile = sample_profile();
        let err = resolve_endpoint(&profile, "dev.ucp.payments", "rest").unwrap_err();
        assert!(err.to_string().contains("no 'dev.ucp.payments' service"));
    }

    #[test]
    fn validate_capabilities_pass() {
        let profile = sample_profile();
        validate_capabilities(&profile, &["dev.ucp.shopping.checkout".to_owned()]).unwrap();
    }

    #[test]
    fn validate_capabilities_fail() {
        let profile = sample_profile();
        let err = validate_capabilities(&profile, &["dev.ucp.payments.subscriptions".to_owned()])
            .unwrap_err();
        assert!(err.to_string().contains("not support"));
    }

    #[test]
    fn cache_expiry() {
        let entry = create_cache_entry(sample_profile(), Duration::from_millis(0));
        assert!(entry.is_expired());

        let entry = create_cache_entry(sample_profile(), Duration::from_secs(3600));
        assert!(!entry.is_expired());
    }
}
