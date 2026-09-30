//! AI assistance in the dashboard: read and generate the explanation of an
//! alert, and try the configuration out once.
//!
//! All of it is reserved for administrators, even plain reading. That looks
//! like too much — a finished explanation costs nothing any more — but it is
//! not: the dossier carries up to sixty lines from an agent's log, and the
//! log itself the central server hands to administrators only
//! (`/api/agents/{id}/log`). If the explanation were readable by everybody, a
//! read-only account would get at exactly those lines by the back door that
//! the route responsible for them denies it — and the summary retells them
//! anyway.

use super::*;
use crate::assist::{self, Insight};

/// State of the service for the dashboard. Nothing here comes from memory:
/// the model is only asked at the press of a button, and whoever clicked
/// sees straight away what went wrong.
#[derive(Serialize)]
pub(super) struct AssistView {
    /// Switch on **and** URL and model set.
    active: bool,
    /// Base URL and model, exactly as stored. No secret — the key never goes
    /// out.
    endpoint: String,
    model: String,
    /// The central server talks to a service outside this network.
    external: bool,
    /// Explanations today (UTC) and the daily budget.
    today: i64,
    daily_limit: i64,
    /// Explanations in total.
    stored: i64,
}

pub(super) async fn assist(State(st): State<Shared>, _u: Admin) -> R<AssistView> {
    let cfg = assist::config(&st.pool).await?;
    let (stored,): (i64,) = sqlx::query_as("SELECT count(*) FROM alert_insights")
        .fetch_one(&st.pool)
        .await?;
    Ok(Json(AssistView {
        active: cfg.is_some(),
        endpoint: cfg.as_ref().map(|c| c.endpoint()).unwrap_or_default(),
        model: cfg.as_ref().map(|c| c.model.clone()).unwrap_or_default(),
        external: cfg.as_ref().is_some_and(|c| c.external()),
        today: assist::used_today(&st.pool).await?,
        daily_limit: db::setting_i64(&st.pool, "assist_daily_limit", 50).await?,
        stored,
    }))
}

/// What has already been written about this alert. `null` if nothing yet —
/// not a 404: „there is no explanation" is an answer, not an error.
pub(super) async fn insight(
    State(st): State<Shared>,
    _u: Admin,
    Path(id): Path<i64>,
) -> R<Option<Insight>> {
    Ok(Json(assist::cached(&st.pool, id).await?))
}

/// „Explain": assembles the dossier, asks the model, stores both.
///
/// The provider's error goes back unchanged. „model 'lama3' not found" or
/// „connection refused" tell an administrator exactly what is wrong with the
/// configuration; any wording of our own would be less precise.
pub(super) async fn explain(
    State(st): State<Shared>,
    Admin(user): Admin,
    Path(id): Path<i64>,
) -> R<Insight> {
    let Some(cfg) = assist::config(&st.pool).await? else {
        return Err(bad(
            "AI assistance is off or incomplete (Settings -> Assistant)",
        ));
    };
    if assist::used_today(&st.pool).await? >= cfg.daily_limit {
        return Err(bad(
            "daily budget for explanations spent, try again tomorrow",
        ));
    }
    let Some(prompt) = assist::dossier(&st.pool, id).await? else {
        return Err(not_found());
    };
    let client = assist::client().map_err(|e| bad(e.to_string()))?;
    let summary = assist::ask(&client, &cfg, &prompt)
        .await
        .map_err(|e| bad(e.to_string()))?;
    let out = assist::store(&st.pool, id, &cfg, &prompt, &summary, (user.id, &user.name)).await?;
    // What gets logged is that a question was asked and where it went — not
    // the dossier: that is stored in full on the alert, and the audit log is
    // not a second copy of the alert data.
    db::audit(&st.pool, (&user).into(), assist::AUDIT_ACTION, json!({ "alert": id, "endpoint": out.endpoint, "model": out.model, "external": cfg.external() })).await;
    Ok(Json(out))
}

/// „Test connection": one question without any alert data, just to check the
/// URL, the key and the model name. With the **stored** settings — so
/// whoever changed something saves first.
#[derive(Serialize)]
pub(super) struct Probe {
    endpoint: String,
    model: String,
    external: bool,
    /// What the model answered. „ready" is expected; but all that matters is
    /// that anything came back at all.
    reply: String,
}

pub(super) async fn test(State(st): State<Shared>, Admin(user): Admin) -> R<Probe> {
    let Some(cfg) = assist::config(&st.pool).await? else {
        return Err(bad("AI assistance is off or incomplete (switch it on, enter a base URL and a model, then save)"));
    };
    // The test counts against the same daily budget as an explanation. It is
    // short, but with a paid service it costs too — and a button without a
    // brake is no button.
    if assist::used_today(&st.pool).await? >= cfg.daily_limit {
        return Err(bad(
            "daily budget spent, try again tomorrow (or raise it above)",
        ));
    }
    let client = assist::client().map_err(|e| bad(e.to_string()))?;
    let outcome = assist::probe(&client, &cfg).await;
    db::audit(
        &st.pool,
        (&user).into(),
        assist::AUDIT_TEST,
        json!({ "endpoint": cfg.endpoint(), "model": cfg.model, "ok": outcome.is_ok() }),
    )
    .await;
    let reply = outcome.map_err(|e| bad(e.to_string()))?;
    Ok(Json(Probe {
        endpoint: cfg.endpoint(),
        model: cfg.model.clone(),
        external: cfg.external(),
        // A talkative model answers with a sentence instead of a word; only
        // one line fits into the message anyway.
        reply: reply.chars().take(200).collect(),
    }))
}
