use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use serde::{Deserialize, Serialize};

const POLICIES: &str = include_str!("../../../policies/finance.cedar");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invocation {
    pub tool: String,
    pub invoice_id: Option<String>,
    pub amount_cents: Option<i64>,
    pub draft_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub agent_id: Option<String>,
    pub role: Option<String>,
    pub untrusted_text: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionReport {
    pub disposition: String,
    pub reason_code: String,
    pub policy_references: Vec<String>,
}

pub fn action_for_tool(tool: &str) -> Option<&'static str> {
    match tool {
        "read_invoice" => Some("invoice.read"),
        "list_invoices" => Some("invoice.list"),
        "read_payment_draft" => Some("payment_draft.read"),
        "create_payment_draft" => Some("payment_draft.create"),
        "request_payment_approval" => Some("payment.approval_request"),
        _ => None,
    }
}

pub fn cedar_allows(
    principal_type: &str,
    principal: &str,
    action: &str,
    resource: &str,
) -> Result<(bool, Vec<String>), String> {
    cedar_allows_with_policy(POLICIES, principal_type, principal, action, resource)
}

pub fn cedar_allows_with_policy(
    policy_source: &str,
    principal_type: &str,
    principal: &str,
    action: &str,
    resource: &str,
) -> Result<(bool, Vec<String>), String> {
    let policies: PolicySet = policy_source
        .parse()
        .map_err(|e| format!("policy parse: {e}"))?;
    let p: EntityUid = format!(r#"{principal_type}::"{principal}""#)
        .parse()
        .map_err(|e| format!("principal: {e}"))?;
    let a: EntityUid = format!(r#"Action::"{action}""#)
        .parse()
        .map_err(|e| format!("action: {e}"))?;
    let r: EntityUid = format!(r#"Resource::"{resource}""#)
        .parse()
        .map_err(|e| format!("resource: {e}"))?;
    let request =
        Request::new(p, a, r, Context::empty(), None).map_err(|e| format!("request: {e}"))?;
    let result = Authorizer::new().is_authorized(&request, &policies, &Entities::empty());
    Ok((
        result.decision() == Decision::Allow,
        result
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect(),
    ))
}

pub fn validate_policies() -> Result<(), String> {
    validate_policy_source(POLICIES)
}

pub fn validate_policy_source(policy_source: &str) -> Result<(), String> {
    let (schema, _) =
        Schema::from_cedarschema_str(include_str!("../../../policies/schema.cedarschema"))
            .map_err(|error| format!("Cedar schema error: {error}"))?;
    let policies: PolicySet = policy_source
        .parse()
        .map_err(|error| format!("Cedar policy parse error: {error}"))?;
    let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
    if result.validation_passed() {
        Ok(())
    } else {
        Err(format!(
            "Cedar policy validation failed: {:?}",
            result.validation_errors().collect::<Vec<_>>()
        ))
    }
}

pub fn authorize_agent(
    agent_id: &str,
    tool: &str,
    tenant: &str,
    resource_tenant: &str,
    delegation_valid: bool,
    user_authorized: bool,
) -> DecisionReport {
    let Some(action) = action_for_tool(tool) else {
        return deny("UNKNOWN_TOOL");
    };
    if tenant != resource_tenant {
        return deny("CROSS_TENANT");
    }
    if !delegation_valid {
        return deny("INVALID_DELEGATION");
    }
    if !user_authorized {
        return deny("USER_PERMISSION_DENIED");
    }
    match cedar_allows("Agent", agent_id, action, resource_tenant) {
        Ok((true, refs)) => DecisionReport {
            disposition: if action == "payment.approval_request" {
                "APPROVAL_REQUIRED"
            } else {
                "ALLOW"
            }
            .into(),
            reason_code: if action == "payment.approval_request" {
                "HUMAN_APPROVAL_REQUIRED"
            } else {
                "AUTHORIZED"
            }
            .into(),
            policy_references: refs,
        },
        Ok((false, _)) => deny("POLICY_DENY"),
        Err(_) => deny("POLICY_ERROR"),
    }
}

fn deny(reason: &str) -> DecisionReport {
    DecisionReport {
        disposition: "DENY".into(),
        reason_code: reason.into(),
        policy_references: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cedar_permits_registered_agent_read() {
        assert!(
            cedar_allows("Agent", "finance-bot", "invoice.read", "acme")
                .unwrap()
                .0
        );
    }
    #[test]
    fn shipped_cedar_policies_validate_against_schema() {
        validate_policies().unwrap();
    }
    #[test]
    fn versioned_policy_can_revoke_a_previously_permitted_action() {
        let source = POLICIES.replace(
            "permit(principal == User::\"owen\", action == Action::\"payment.submit\", resource);\n",
            "",
        );
        validate_policy_source(&source).unwrap();
        assert!(
            !cedar_allows_with_policy(&source, "User", "owen", "payment.submit", "acme")
                .unwrap()
                .0
        );
        assert!(
            cedar_allows("User", "owen", "payment.submit", "acme")
                .unwrap()
                .0
        );
    }
    #[test]
    fn unknown_tool_defaults_to_deny() {
        assert_eq!(
            authorize_agent("finance-bot", "shell", "acme", "acme", true, true).reason_code,
            "UNKNOWN_TOOL"
        );
    }
    #[test]
    fn tenant_mismatch_is_denied() {
        assert_eq!(
            authorize_agent(
                "finance-bot",
                "read_invoice",
                "acme",
                "northstar",
                true,
                true
            )
            .disposition,
            "DENY"
        );
    }
    #[test]
    fn expired_delegation_is_denied() {
        assert_eq!(
            authorize_agent("finance-bot", "read_invoice", "acme", "acme", false, true).reason_code,
            "INVALID_DELEGATION"
        );
    }
    #[test]
    fn delegation_scope_cannot_expand_the_user_permission_set() {
        let result = authorize_agent(
            "finance-bot",
            "create_payment_draft",
            "acme",
            "acme",
            true,
            false,
        );
        assert_eq!(result.disposition, "DENY");
        assert_eq!(result.reason_code, "USER_PERMISSION_DENIED");
    }
    #[test]
    fn action_outside_delegation_scope_is_denied() {
        let result = authorize_agent("finance-bot", "read_invoice", "acme", "acme", false, true);
        assert_eq!(result.disposition, "DENY");
        assert_eq!(result.reason_code, "INVALID_DELEGATION");
    }
}
