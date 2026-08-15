//! Checkout session management for UCP commerce plugin.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Checkout session state
// ---------------------------------------------------------------------------

/// Status of a UCP checkout session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutStatus {
    /// Session created, items being added.
    Incomplete,
    /// Merchant requires additional info (address, shipping).
    RequiresAction,
    /// All required fields filled, ready for payment.
    ReadyForComplete,
    /// Complete in progress.
    CompleteInProgress,
    /// Session successfully completed.
    Completed,
    /// Session canceled.
    Canceled,
}

/// An active UCP checkout session.
#[derive(Debug)]
pub struct UcpCheckoutSession {
    /// Merchant-assigned session ID.
    pub session_id: String,
    /// Ownership key of the principal that created this session. Only
    /// that principal may address it later (IDOR guard). Set by the
    /// gate after construction; empty until then.
    pub owner: String,
    /// Current session status.
    pub status: CheckoutStatus,
    /// Merchant base URL.
    pub merchant_url: String,
    /// Merchant endpoint URL.
    pub merchant_endpoint: String,
    /// Transport type.
    pub transport: SessionTransport,
    /// Full checkout response (last known state).
    pub last_response: Value,
    /// When this session was created.
    pub created_at: std::time::Instant,
}

/// Transport used for a checkout session.
#[derive(Debug, Clone)]
pub enum SessionTransport {
    Mcp { endpoint: String },
    Rest { endpoint: String },
}

impl UcpCheckoutSession {
    /// Create a new session from a merchant response.
    pub fn from_response(
        response: Value,
        merchant_url: String,
        merchant_endpoint: String,
        transport: SessionTransport,
    ) -> Option<Self> {
        let session_id = response.get("id").and_then(|v| v.as_str())?.to_owned();

        let status = response
            .get("status")
            .and_then(|v| v.as_str())
            .map(parse_status)
            .unwrap_or(CheckoutStatus::Incomplete);

        Some(Self {
            session_id,
            owner: String::new(),
            status,
            merchant_url,
            merchant_endpoint,
            transport,
            last_response: response,
            created_at: std::time::Instant::now(),
        })
    }

    /// Update the session with a new response.
    pub fn update_from_response(&mut self, response: Value) {
        if let Some(status) = response.get("status").and_then(|v| v.as_str()) {
            self.status = parse_status(status);
        }
        self.last_response = response;
    }

    /// Check if the session has expired.
    pub fn is_expired(&self, ttl: std::time::Duration) -> bool {
        self.created_at.elapsed() >= ttl
    }

    /// Has the merchant reported this checkout as settled (paid)?
    ///
    /// This is the security gate for granting the tool call: only a
    /// `Completed` status counts. Every other status — including a
    /// missing status, which parses as `Incomplete` — means payment is
    /// NOT confirmed and the call must be re-challenged, never allowed.
    pub fn is_settled(&self) -> bool {
        self.status == CheckoutStatus::Completed
    }

    /// Build the challenge data to return to the client.
    pub fn build_challenge_data(&self) -> Value {
        let mut data = serde_json::json!({
            "protocol": "ucp",
            "httpStatus": 402,
            "checkout_session": self.last_response,
        });

        // Extract payment handlers if present
        if let Some(payment) = self.last_response.get("payment")
            && let Some(instruments) = payment.get("instruments")
        {
            data["available_payment_instruments"] = instruments.clone();
        }

        data
    }

    /// Build the order metadata for a completed session.
    ///
    /// Emits only the merchant's real `order` object. It must NOT
    /// fabricate a synthetic `{status:"completed"}` receipt — a receipt
    /// has to reflect the merchant's actual settlement, never a
    /// gateway-invented success. The gate only calls this after it has
    /// confirmed `status == Completed`, so a missing `order` here means a
    /// malformed merchant completion; emit a bare session reference (no
    /// invented status field) rather than claim a settlement we can't see.
    pub fn build_order_meta(&self) -> Value {
        let order = self
            .last_response
            .get("order")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({ "checkout_id": self.session_id }));

        serde_json::json!({
            "ucp/order": order
        })
    }
}

/// Parse a UCP status string into our enum.
fn parse_status(s: &str) -> CheckoutStatus {
    match s {
        "incomplete" => CheckoutStatus::Incomplete,
        "requires_action" => CheckoutStatus::RequiresAction,
        "ready_for_complete" | "ready" => CheckoutStatus::ReadyForComplete,
        "complete_in_progress" => CheckoutStatus::CompleteInProgress,
        "completed" => CheckoutStatus::Completed,
        "canceled" | "cancelled" => CheckoutStatus::Canceled,
        _ => CheckoutStatus::Incomplete,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_from_response() {
        let response = serde_json::json!({
            "id": "chk_123",
            "status": "incomplete",
            "line_items": [{ "name": "Widget", "total": 2999 }],
            "totals": [{ "type": "total", "amount": 3249 }]
        });

        let session = UcpCheckoutSession::from_response(
            response,
            "https://merchant.example.com".into(),
            "https://merchant.example.com/mcp".into(),
            SessionTransport::Mcp {
                endpoint: "https://merchant.example.com/mcp".into(),
            },
        )
        .unwrap();

        assert_eq!(session.session_id, "chk_123");
        assert_eq!(session.status, CheckoutStatus::Incomplete);
    }

    #[test]
    fn session_update() {
        let mut session = UcpCheckoutSession::from_response(
            serde_json::json!({ "id": "chk_1", "status": "incomplete" }),
            "https://m.example.com".into(),
            "https://m.example.com/api".into(),
            SessionTransport::Rest {
                endpoint: "https://m.example.com/api".into(),
            },
        )
        .unwrap();

        assert_eq!(session.status, CheckoutStatus::Incomplete);

        session.update_from_response(serde_json::json!({
            "id": "chk_1",
            "status": "ready_for_complete",
            "order": { "id": "order_1" }
        }));

        assert_eq!(session.status, CheckoutStatus::ReadyForComplete);
    }

    #[test]
    fn session_challenge_data() {
        let session = UcpCheckoutSession::from_response(
            serde_json::json!({
                "id": "chk_1",
                "status": "incomplete",
                "payment": { "instruments": [{ "type": "card" }] }
            }),
            "https://m.example.com".into(),
            "https://m.example.com/api".into(),
            SessionTransport::Rest {
                endpoint: "https://m.example.com/api".into(),
            },
        )
        .unwrap();

        let data = session.build_challenge_data();
        assert_eq!(data["protocol"], "ucp");
        assert_eq!(data["httpStatus"], 402);
        assert!(data["available_payment_instruments"].is_array());
    }

    #[test]
    fn session_order_meta() {
        let mut session = UcpCheckoutSession::from_response(
            serde_json::json!({ "id": "chk_1", "status": "completed" }),
            "https://m.example.com".into(),
            "https://m.example.com/api".into(),
            SessionTransport::Rest {
                endpoint: "https://m.example.com/api".into(),
            },
        )
        .unwrap();

        session.update_from_response(serde_json::json!({
            "id": "chk_1",
            "status": "completed",
            "order": { "id": "order_456", "permalink_url": "https://m.example.com/orders/456" }
        }));

        let meta = session.build_order_meta();
        assert_eq!(meta["ucp/order"]["id"], "order_456");
    }

    #[test]
    fn session_expiry() {
        let session = UcpCheckoutSession::from_response(
            serde_json::json!({ "id": "chk_1", "status": "incomplete" }),
            "https://m.example.com".into(),
            "https://m.example.com/api".into(),
            SessionTransport::Rest {
                endpoint: "https://m.example.com/api".into(),
            },
        )
        .unwrap();

        assert!(!session.is_expired(std::time::Duration::from_secs(3600)));
        assert!(session.is_expired(std::time::Duration::from_millis(0)));
    }

    #[test]
    fn parse_all_statuses() {
        assert_eq!(parse_status("incomplete"), CheckoutStatus::Incomplete);
        assert_eq!(
            parse_status("requires_action"),
            CheckoutStatus::RequiresAction
        );
        assert_eq!(
            parse_status("ready_for_complete"),
            CheckoutStatus::ReadyForComplete
        );
        assert_eq!(parse_status("ready"), CheckoutStatus::ReadyForComplete);
        assert_eq!(parse_status("completed"), CheckoutStatus::Completed);
        assert_eq!(parse_status("canceled"), CheckoutStatus::Canceled);
        assert_eq!(parse_status("cancelled"), CheckoutStatus::Canceled);
        assert_eq!(parse_status("unknown"), CheckoutStatus::Incomplete);
    }

    fn mk(status_json: Value) -> UcpCheckoutSession {
        UcpCheckoutSession::from_response(
            status_json,
            "https://m.example.com".into(),
            "https://m.example.com/api".into(),
            SessionTransport::Rest {
                endpoint: "https://m.example.com/api".into(),
            },
        )
        .unwrap()
    }

    // SECURITY (payment bypass): the completion gate grants the tool call
    // only when the merchant reports `completed`. A non-error HTTP response
    // with any other status — or no status at all — is NOT proof of payment.
    #[test]
    fn only_completed_is_settled() {
        for s in [
            "incomplete",
            "requires_action",
            "ready_for_complete",
            "complete_in_progress",
            "canceled",
        ] {
            let sess = mk(serde_json::json!({ "id": "chk", "status": s }));
            assert!(!sess.is_settled(), "status {s:?} must NOT be settled");
        }
        // Missing status parses as Incomplete → not settled.
        let no_status = mk(serde_json::json!({ "id": "chk" }));
        assert!(
            !no_status.is_settled(),
            "missing status must NOT be settled"
        );
        // Only `completed` settles.
        let done = mk(serde_json::json!({ "id": "chk", "status": "completed" }));
        assert!(done.is_settled());
    }

    // A non-error completion response that omits `order` must NOT be turned
    // into a fabricated `{status:"completed"}` receipt.
    #[test]
    fn order_meta_does_not_fabricate_completed_status() {
        let sess = mk(serde_json::json!({ "id": "chk_77", "status": "completed" }));
        let meta = sess.build_order_meta();
        let order = &meta["ucp/order"];
        assert_eq!(order["checkout_id"], "chk_77");
        assert!(
            order.get("status").is_none(),
            "build_order_meta must not invent a status field: {order}"
        );
    }
}
