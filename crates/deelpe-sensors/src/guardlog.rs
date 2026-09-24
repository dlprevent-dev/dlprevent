//! Verdicts of the LLM guard (`dlprevent-guard`), out of its log.
//!
//! The guard runs as a container between the agent and its model and
//! writes one JSON line per finding to a file on the host. This sensor
//! reads that file the way [`crate::hermes`] reads the session logs — a
//! byte offset, new lines every few seconds — and hands each line on as
//! [`Event::Guard`]. The correlator makes an alert of it.

use crate::Sensor;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deelpe_core::event::{Event, GuardEvent};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;

/// Where the guard's compose file mounts its log.
const LOG: &str = "/var/log/dlprevent-guard/verdicts.jsonl";
const POLL: Duration = Duration::from_secs(2);

pub struct GuardLog;

#[async_trait]
impl Sensor for GuardLog {
    fn name(&self) -> &'static str {
        "llm guard"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        // What the log held before the service started is not news.
        let mut offset = std::fs::metadata(LOG).map(|m| m.len()).unwrap_or(0);
        loop {
            if let Ok(lines) = crate::hermes::read_new(Path::new(LOG), &mut offset) {
                for ev in lines.lines().filter_map(parse_line) {
                    if tx.send(Event::Guard(ev)).await.is_err() {
                        return Ok(());
                    }
                }
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

/// One verdict line. A line that is not one is skipped: the log is written
/// by another program, and one broken line must not stop the rest.
pub fn parse_line(line: &str) -> Option<GuardEvent> {
    let v: Value = serde_json::from_str(line).ok()?;
    let s = |k: &str| v[k].as_str().map(str::to_string);
    let layers = v["layers"].as_array().cloned().unwrap_or_default();
    Some(GuardEvent {
        at: s("at").and_then(|t| DateTime::parse_from_rfc3339(&t).ok()).map_or_else(Utc::now, |t| t.with_timezone(&Utc)),
        direction: s("direction")?,
        verdict: s("verdict")?,
        blocked: v["action"].as_str() == Some("blocked"),
        model: s("model"),
        origin: s("origin"),
        rules: layers.iter().filter_map(|l| l["rule"].as_str().or(l["layer"].as_str()).map(str::to_string)).collect(),
        reason: layers.first().and_then(|l| l["reason"].as_str()).map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line exactly as the guard wrote it in the container test.
    const LINE: &str = r#"{"at":"2026-09-24T10:47:03.218Z","direction":"tool_result","verdict":"block","action":"forwarded","model":"m","origin":"web_extract","chars":90,"layers":[{"layer":"injection","rule":"ignore_prior_instructions","verdict":"block","reason":"Attempt to override prior system or developer instructions."},{"layer":"injection","rule":"retrieved_instruction_override","verdict":"block","reason":"Override-style instruction."}]}"#;

    #[test]
    fn a_verdict_line_becomes_an_event() {
        let g = parse_line(LINE).unwrap();
        assert_eq!(g.direction, "tool_result");
        assert!(!g.blocked, "flag mode forwards");
        assert_eq!(g.origin.as_deref(), Some("web_extract"));
        assert_eq!(g.rules, ["ignore_prior_instructions", "retrieved_instruction_override"]);
        assert_eq!(g.reason.as_deref(), Some("Attempt to override prior system or developer instructions."));
        assert_eq!(g.at.to_rfc3339(), "2026-09-24T10:47:03.218+00:00");
        assert!(parse_line(&LINE.replace("forwarded", "blocked")).unwrap().blocked);
    }

    #[test]
    fn a_broken_line_is_skipped() {
        assert!(parse_line("{not json").is_none());
        assert!(parse_line(r#"{"at":"x"}"#).is_none(), "no direction, no verdict");
    }
}
