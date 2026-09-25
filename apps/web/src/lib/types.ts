export type Role = 'admin' | 'viewer';
/** `second_factor_required`: the role has to have a second factor and the
 *  account has none — until then the server only allows the account page. */
export interface User { id: string; name: string; role: Role; second_factor_required: boolean ; timezone?: string }
export interface Alert {
  id: number; kind: 'endpoint' | 'access'; agent_id: string | null; source_id: string | null; origin_name: string;
  external_id: string; at: string; last_at: string | null; user_key: string | null; user_display: string | null;
  rule_id: string | null; path: string | null; process: string | null; files: string[]; file_count: number; bytes: number;
  remote: string | null; verdict: string; reason: string | null; detail: unknown; acknowledged_at: string | null;
  acknowledged_by: string | null; received_at: string;
}
export interface Rule {
  id: string; name: string; path: string; scope: 'all' | 'agent' | 'source'; agent_id: string | null; source_id: string | null;
  allowed_groups: string[]; lockdown: boolean; strict: boolean; allow_destinations: string[]; enforce: boolean;
  hard_max_files: number; window_secs: number; ad_lock: boolean; enabled: boolean;
  created_at: string; updated_at: string;
}
export interface ShareInfo {
  name: string;
  path?: string;
  remark?: string;
  /** "enum" = from the share table, "events" = learned from accesses. */
  path_from?: string;
}

export interface Agent {
  id: string; name: string; kind: string; version: string; cert_fingerprint: string; cert_not_after: string; enrolled_at: string;
  last_seen: string | null; last_addr: string | null; status: AgentStatus | null; revoked_at: string | null; online: boolean;
  /** When somebody requested an update for this agent. `null` means none is pending. */
  update_requested: string | null;
  /** When somebody asked this agent to finish its learning phase. `null` means none is pending. */
  learn_confirm_requested: string | null;
}
export interface AgentStatus { version: string; /** First twelve hex digits of the SHA-256 of the agent file; empty on older agents. */ build?: string; hostname: string; /** Fully qualified name, if the device carries one; empty on older agents and outside a domain. */ fqdn?: string; started_at: string; sensors: { name: string; ok: boolean; error?: string }[]; watched: string[]; learn_phase: string; shares?: ShareInfo[]; addrs?: string[]; /** `amd64`/`arm64`; empty on agents older than 0.1.4. */ arch?: string; /** End of the learning phase, the start of review; absent on file servers and older agents. */ learn_until?: string }
/** One row from an agent's local log. */
export interface LogRow { id: number; at: string; level: string; target: string; msg: string }
export interface Source { id: string; name: string; kind: string; address: string; first_seen: string; last_seen: string | null; lines: number; unparsed: number }
export interface Token { id: string; label: string; created_at: string; expires_at: string; used_at: string | null; used_by: string | null; max_uses: number | null; uses: number }
export interface TokenCreated { id: string; token: string; expires_at: string; agent_url: string; ca_sha256: string; command: string; enroll_command: string | null }
export interface UserRow { id: string; name: string; role: Role; disabled: boolean; external: boolean; created_at: string; last_login: string | null; totp_enabled: boolean; passkeys: number }
/** `abuseipdb_key` and `smtp_pass` only go in, never out: the server never
 *  sends them along. Empty means "unchanged", a single dash means "delete".
 *  Whether one is set is told by `abuseipdb_key_set` and
 *  `smtp_pass_set`. */
export interface Settings { allow_processes: string; learn_days: number; report_interval_secs: number; alert_retain_days: number; count_retain_days: number; learn_push_enabled: boolean; agent_update_enabled: boolean; release_repo: string; release_check_enabled: boolean; release_pubkey: string; release_token?: string; release_token_set: boolean; release_pubkey_built_in: boolean; syslog_enabled: boolean; api_keys_enabled: boolean; require_2fa_admin: boolean; require_2fa_viewer: boolean; abuseipdb_enabled: boolean; abuseipdb_key?: string; abuseipdb_key_set: boolean; abuseipdb_daily_limit: number;
  smtp_enabled: boolean; smtp_host: string; smtp_port: number; smtp_security: 'starttls' | 'tls' | 'none';
  smtp_user: string; smtp_pass?: string; smtp_pass_set: boolean; smtp_from: string; smtp_to: string;
  notify_base_url: string; notify_alerts: boolean; notify_agent_down: boolean; notify_abuse_ip: boolean;
  notify_abuse_min_score: number; notify_digest_mins: number; notify_agent_down_mins: number; report_timezone: string;
  assist_enabled: boolean; assist_base_url: string; assist_model: string; assist_key?: string; assist_key_set: boolean; assist_daily_limit: number;
  config_generation: number }
/** Response of `/api/notifications`: the state of mail delivery. `active`
 *  means the switch is on **and** the setup is complete. */
export interface NotifyView {
  active: boolean; recipients: number; sent: number; last_sent_at: string | null; last_error: string | null;
}
/** Reputation of a destination address per AbuseIPDB, from the central cache. */
export interface Reputation {
  ip: string; score: number; country_code: string | null; isp: string | null; domain: string | null;
  usage_type: string | null; total_reports: number; is_tor: boolean; is_whitelisted: boolean; checked_at: string;
}
/** Response of `/api/reputation`: the addresses asked about plus the state of the service. */
export interface ReputationView {
  active: boolean; items: Reputation[]; cached: number; today: number; daily_limit: number;
  lookups: number; last_error: string | null; paused_until: string | null;
}
/** The explanation a model wrote about an alert. `prompt` is, word for word,
 *  the dossier that went out for it — in a tool against data leakage it has to
 *  stay possible to look up what left the building. */
export interface Insight {
  alert_id: number; model: string; endpoint: string; prompt: string; summary: string;
  created_at: string; created_by_name: string;
}
/** Response of `/api/assist`: state of the AI assistance. `external` means
 *  that the endpoint lies outside this network. */
export interface AssistView {
  active: boolean; endpoint: string; model: string; external: boolean;
  today: number; daily_limit: number; stored: number;
}
/** Response of `/api/assist/test`: what came out of "Test connection". */
export interface AssistProbe { endpoint: string; model: string; external: boolean; reply: string }
/** A passkey of your own account; the key itself stays with the server. */
export interface Passkey { id: string; label: string; created_at: string; last_used_at: string | null }
export interface Account { totp_enabled: boolean; passkeys: Passkey[] }
/** Only during setup: afterwards the server never shows the secret again. */
export interface TotpSetup { secret: string; otpauth: string; qr_svg: string }
/** Key for third-party access to the read API. An empty `expires_at` means:
 *  it does not expire. */
export interface ApiKey { id: string; label: string; created_at: string; expires_at: string | null; last_used_at: string | null }
/** Only the response to creation carries the plaintext — never again after. */
export interface ApiKeyCreated extends ApiKey { key: string }
export interface AuditRow { id: number; at: string; user_name: string; action: string; detail: unknown }
export interface Overview {
  agents: number; agents_online: number; sources: number; rules: number; alerts_open: number; alerts_24h: number;
  recent: Alert[]; ca_fingerprint: string; server_started: string; api_version: number;
  /** `server_build` is empty when the server cannot read its own file. */
  server_version: string; server_build: string;
}
export interface Counts { hours: number; per_hour: { hour: string; files: number; bytes: number }[]; top: { user_display: string; path: string; files: number; bytes: number }[] }

/// Agent binary that the central server keeps ready for download.
/// The Windows workstation and file server share one file.
/** The state of the release. `tag` is what exists over there,
 *  `installed_tag` what this central server has actually fetched of it. */
export interface ReleaseView {
  check_enabled: boolean; repo: string; key_set: boolean; key_built_in: boolean; installed_tag: string;
  installed_platforms: string[];
  /** Is the master switch on? Then fetching is rolling out at the same time. */
  rolls_out_at_once: boolean;
  checked_at: string | null; tag: string | null; published_at: string | null; url: string | null;
  platforms: string[]; error: string | null;
}
export interface Binary {
  platform: 'windows' | 'mac' | 'linux-amd64' | 'linux-arm64';
  file_name: string;
  present: boolean;
  size: number;
  sha256: string;
  uploaded_at: string | null;
}
