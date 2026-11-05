use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value};
use time::{Date, OffsetDateTime, macros::format_description};

use crate::findings::Finding;

use super::{finding, line_containing};

const EXPIRED_FLAG: &str = "feature-flag-expired";
const INVALID_ALLOCATION: &str = "feature-rollout-allocation-invalid";
const EXPIRY_KEYS: &[&str] = &["expiry", "expires", "expiresAt", "expires_at"];
const PERCENTAGE_KEYS: &[&str] = &[
    "percentage",
    "allocationPercentage",
    "allocation_percentage",
    "rolloutPercentage",
    "rollout_percentage",
];

pub(super) fn analyze(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in auxiliary
        .iter()
        .filter(|(path, _)| is_feature_registry(path))
    {
        let Ok(document) = serde_json::from_str::<Value>(source) else {
            continue;
        };
        if let Some((name, expiry)) = first_expired_flag(&document) {
            findings.push(finding(
                EXPIRED_FLAG,
                path,
                line_containing(source, expiry),
                format!("feature flag `{name}` expired on {expiry}"),
                Vec::new(),
            ));
        }
        if let Some(violation) = invalid_in_value(&document) {
            findings.push(finding(
                INVALID_ALLOCATION,
                path,
                line_containing(source, violation.needle),
                violation.message,
                Vec::new(),
            ));
        }
    }
    findings
}

fn first_expired_flag(document: &Value) -> Option<(String, &str)> {
    entries(document).find_map(|entry| {
        let expiry = EXPIRY_KEYS
            .iter()
            .find_map(|key| entry.get(*key).and_then(Value::as_str))?;
        let date = Date::parse(expiry, format_description!("[year]-[month]-[day]")).ok()?;
        if date >= OffsetDateTime::now_utc().date() {
            return None;
        }
        Some((entry_name(entry), expiry))
    })
}

struct AllocationViolation<'a> {
    needle: &'a str,
    message: String,
}

fn invalid_in_value(value: &Value) -> Option<AllocationViolation<'_>> {
    match value {
        Value::Object(object) => {
            invalid_percentage(object).or_else(|| invalid_object_children(object))
        }
        Value::Array(values) => values.iter().find_map(invalid_in_value),
        _ => None,
    }
}

fn invalid_percentage(object: &Map<String, Value>) -> Option<AllocationViolation<'_>> {
    PERCENTAGE_KEYS.iter().find_map(|key| {
        let number = object.get(*key).and_then(Value::as_f64)?;
        (!(0.0..=100.0).contains(&number)).then(|| AllocationViolation {
            needle: key,
            message: format!("rollout percentage {number} is outside 0 through 100"),
        })
    })
}

fn invalid_object_children(object: &Map<String, Value>) -> Option<AllocationViolation<'_>> {
    for (key, child) in object {
        if matches!(key.as_str(), "variants" | "allocations" | "treatments")
            && let Some(violation) = invalid_exclusive_allocations(child)
        {
            return Some(violation);
        }
        if let Some(violation) = invalid_in_value(child) {
            return Some(violation);
        }
    }
    None
}

fn invalid_exclusive_allocations(value: &Value) -> Option<AllocationViolation<'_>> {
    let percentages = value
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .filter_map(explicit_percentage)
        .collect::<Vec<_>>();
    if percentages.len() < 2 {
        return None;
    }
    let total = percentages.iter().map(|(_, value)| value).sum::<f64>();
    (total > 100.0 + f64::EPSILON).then(|| AllocationViolation {
        needle: percentages[0].0,
        message: format!("mutually exclusive rollout percentages total {total}, above 100"),
    })
}

fn explicit_percentage(object: &Map<String, Value>) -> Option<(&str, f64)> {
    PERCENTAGE_KEYS.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_f64)
            .map(|value| (*key, value))
    })
}

fn entries(document: &Value) -> Box<dyn Iterator<Item = &Map<String, Value>> + '_> {
    let value = document
        .as_object()
        .and_then(|object| {
            ["flags", "features", "experiments"]
                .iter()
                .find_map(|key| object.get(*key))
        })
        .unwrap_or(document);
    match value {
        Value::Array(values) => Box::new(values.iter().filter_map(Value::as_object)),
        Value::Object(object) => Box::new(object.values().filter_map(Value::as_object)),
        _ => Box::new(std::iter::empty()),
    }
}

fn entry_name(entry: &Map<String, Value>) -> String {
    ["key", "name", "id"]
        .iter()
        .find_map(|key| entry.get(*key).and_then(Value::as_str))
        .unwrap_or("unnamed")
        .to_owned()
}

fn is_feature_registry(path: &str) -> bool {
    matches!(
        Path::new(path).file_name().and_then(|name| name.to_str()),
        Some("feature-flags.json" | "feature_flags.json")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_expired_flags_and_invalid_percentages() {
        let files = BTreeMap::from([(
            "config/feature-flags.json".to_owned(),
            r#"{"flags":[{"name":"old-checkout","expiry":"2000-01-01","percentage":120},{"name":"new-checkout","expiry":"2999-01-01","percentage":20}]}"#.to_owned(),
        )]);
        let findings = analyze(&files);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            [EXPIRED_FLAG, INVALID_ALLOCATION]
        );
    }

    #[test]
    fn reports_exclusive_allocations_over_one_hundred() {
        let files = BTreeMap::from([(
            "feature_flags.json".to_owned(),
            r#"{"flags":{"checkout":{"name":"checkout","expiry":"2999-01-01","variants":[{"name":"a","percentage":60},{"name":"b","percentage":50}]}}}"#.to_owned(),
        )]);
        let findings = analyze(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, INVALID_ALLOCATION);
    }

    #[test]
    fn accepts_active_flags_non_percentage_weights_and_independent_flag_allocations() {
        let files = BTreeMap::from([(
            "feature-flags.json".to_owned(),
            r#"{"flags":[{"name":"checkout","expiry":"2999-01-01","percentage":60,"variants":[{"weight":60},{"weight":50}]},{"name":"search","expiry":"2999-01-01","percentage":60}]}"#.to_owned(),
        )]);
        assert!(analyze(&files).is_empty());
    }
}
