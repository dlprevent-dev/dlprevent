//! Releases: checking and fetching. Nothing is rolled out here.

use super::*;

#[derive(Serialize)]
pub(super) struct ReleaseView {
    /// Does the central server check on its own?
    check_enabled: bool,
    repo: String,
    /// Is a key available — and is it baked into the program?
    key_set: bool,
    key_built_in: bool,
    /// The version that was actually fetched last, and for which platforms.
    installed_tag: String,
    installed_platforms: Vec<String>,
    /// Is the master switch on? Then fetching **is at the same time**
    /// rolling out: whatever lands in the drop box, the agents pick up by
    /// themselves with their next report. That has to be in the dashboard
    /// before anybody presses the button — otherwise the box promises
    /// "nothing gets distributed" while it is on every workstation within
    /// half a minute.
    rolls_out_at_once: bool,
    #[serde(flatten)]
    status: crate::release::Status,
}

pub(super) async fn release(State(st): State<Shared>, _u: Admin) -> R<ReleaseView> {
    let m = db::settings_map(
        &st.pool,
        &[
            "release_repo",
            "release_check_enabled",
            "release_installed_tag",
            "release_installed_platforms",
            "agent_update_enabled",
        ],
    )
    .await?;
    let str_of = |k: &str| {
        m.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Ok(Json(ReleaseView {
        check_enabled: m
            .get("release_check_enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        repo: str_of("release_repo"),
        key_set: crate::release::pubkey(&st).await?.is_some(),
        key_built_in: crate::release::BUILT_IN_PUBKEY
            .map(str::trim)
            .is_some_and(|k| !k.is_empty()),
        installed_tag: str_of("release_installed_tag"),
        installed_platforms: m
            .get("release_installed_platforms")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        rolls_out_at_once: m
            .get("agent_update_enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        status: st.release.lock().unwrap().clone(),
    }))
}

/// Check now. Changes nothing but the note in memory — that is why being an
/// administrator is enough here, and no confirmation is needed.
pub(super) async fn check(State(st): State<Shared>, _u: Admin) -> R<crate::release::Status> {
    let s = crate::release::check(&st)
        .await
        .map_err(|e| bad(format!("{e:#}")))?;
    Ok(Json(s))
}

/// Fetch the program, verify it and put it in the drop box.
///
/// This is the step that brings something from the network into the
/// installation: it goes into the audit log, with version and platforms.
/// After that, only what somebody explicitly rolls out still reaches the
/// devices.
pub(super) async fn fetch(State(st): State<Shared>, Admin(user): Admin) -> R<serde_json::Value> {
    let (tag, platforms, refused) = crate::release::fetch(&st)
        .await
        .map_err(|e| bad(format!("{e:#}")))?;
    // What was refused goes into the audit log too: that a version only
    // arrived in part is exactly what you go looking for later.
    db::audit(
        &st.pool,
        (&user).into(),
        "release_fetch",
        json!({ "tag": tag, "platforms": platforms, "refused": refused }),
    )
    .await;
    Ok(Json(
        json!({ "tag": tag, "platforms": platforms, "refused": refused }),
    ))
}
