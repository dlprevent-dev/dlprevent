//! Email notification: show the state, send a test message.
//!
//! It is configured in the settings (`api::settings`); here is only what the
//! running sender does — and the button that really does send one email out.
//! That one is reserved for administrators: it talks to a server outside
//! this network.

use super::*;
use crate::mail;

#[derive(Serialize)]
pub(super) struct NotifyView {
    /// Switch on **and** configuration complete: only then is anything sent
    /// at all.
    active: bool,
    /// How many addresses are currently on file.
    recipients: usize,
    /// Emails since the central server started.
    sent: u64,
    last_sent_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

pub(super) async fn notifications(State(st): State<Shared>, _u: Admin) -> R<NotifyView> {
    let cfg = mail::config(&st.pool).await?;
    let status = st.mail.lock().unwrap().clone();
    Ok(Json(NotifyView {
        active: cfg.is_some(),
        recipients: cfg.map(|c| c.to.len()).unwrap_or(0),
        sent: status.sent,
        last_sent_at: status.last_sent_at,
        last_error: status.last_error,
    }))
}

/// „Send test email": sends a message to the configured recipients right
/// away, with the **stored** settings. So whoever changed something saves
/// first — otherwise the test checks the old state.
///
/// The mail server's error goes back unchanged: „authentication failed" or
/// „connection refused" says more than any wording of our own.
pub(super) async fn test(State(st): State<Shared>, Admin(user): Admin) -> R<NotifyView> {
    let cfg = mail::configured(&st.pool).await?.map_err(bad)?;
    let (subject, text, html) = mail::test_message(&cfg, Utc::now());
    let outcome = mail::send(&cfg, &subject, &text, &html).await;
    {
        let mut s = st.mail.lock().unwrap();
        match &outcome {
            // `last_sent_at` stays where it is: it is at the same time the
            // clock of the digest window. If the test moved it forward, one
            // press of the button would push the next real message out by up
            // to `notify_digest_mins` — with a daily window, by a day. The
            // feedback is the counter and the message in the browser.
            Ok(()) => {
                s.sent += 1;
                s.last_error = None;
            }
            Err(e) => s.last_error = Some(e.to_string()),
        }
    }
    db::audit(
        &st.pool,
        (&user).into(),
        "notification_test",
        json!({ "host": cfg.host, "port": cfg.port, "to": cfg.to, "ok": outcome.is_ok() }),
    )
    .await;
    outcome.map_err(|e| bad(e.to_string()))?;
    notifications(State(st), Admin(user)).await
}
