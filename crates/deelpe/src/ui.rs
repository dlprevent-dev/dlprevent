//! Colored tables for the CLI.

use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, Table};
use deelpe::ipc::Response;
use deelpe_core::correlate::{Alert, Target};
use deelpe_core::learn::{LearnStatus, PairState, Phase, Verdict};
use owo_colors::OwoColorize;

pub fn print_response(r: Response) {
    match r {
        Response::Ok(m) => println!("{} {m}", "✓".green()),
        Response::Err(m) => {
            eprintln!("{} {m}", "✗".red());
            // The app calls the CLI as root and needs the failure as an exit code.
            std::process::exit(1);
        }
        Response::Watched(ws) => {
            if ws.is_empty() {
                println!("No protected folders. `deelpe watch add <folder>`");
            }
            for w in ws {
                println!("  {} {}", "🔒".to_string(), w.display());
            }
        }
        Response::Ignored(rules) => {
            if rules.is_empty() {
                println!("No exceptions. `deelpe ignore add <signing-id>`");
            }
            for r in rules {
                println!("  {} {r}", "○".dimmed());
            }
        }
        Response::Alerts(al) => print_alerts(&al),
        Response::Learn(st) => print_learn(&st),
        Response::Central(None) => println!("Not connected to a central server. Enroll: sudo deelpe central enroll <url> <token> --ca-sha256 <fp>"),
        Response::Central(Some(c)) => {
            println!("{} {} as agent {}", "Central".bold(), c.url, c.agent_id);
            println!("  Reports:   {} (configuration generation {})", c.reports, c.generation);
            println!("  Last:      {}", c.last_ok.map(|t| t.to_rfc3339()).unwrap_or_else(|| "never reported".into()));
            if !c.managed.is_empty() {
                println!("  Folders from the central server: {}", c.managed.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "));
            }
            if let Some(e) = c.last_error {
                println!("  {} {e} ({})", "Error:".red(), c.last_error_at.map(|t| t.to_rfc3339()).unwrap_or_default());
            }
        }
        Response::Alert(Some(a)) => print_alert(&a),
        Response::Alert(None) => eprintln!("{} no alert with that id", "✗".red()),
        Response::Status { touched, alerts, watched, uptime_secs, sensors, warnings } => {
            println!("{}", "DLPrevent is running".green().bold());
            for s in &sensors {
                match &s.error {
                    None => println!("  {} {}", "●".green(), s.name),
                    Some(e) => println!("  {} {}: {}", "●".red(), s.name, e.lines().next().unwrap_or("")),
                }
            }
            for w in &warnings {
                println!("  {} {}", "!".red().bold(), w.red());
            }
            println!("  uptime             {}", human_secs(uptime_secs));
            println!("  protected folders  {watched}");
            println!("  touched processes  {touched}");
            println!("  alerts             {}", if alerts > 0 { alerts.to_string().red().to_string() } else { "0".to_string() });
        }
    }
}

fn print_alerts(al: &[Alert]) {
    if al.is_empty() {
        println!("{}", "No alerts.".green());
        return;
    }
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(["id", "time", "verdict", "process", "file", "target", "sent"]);
    for a in al {
        t.add_row([
            Cell::new(a.id),
            Cell::new(a.at.with_timezone(&chrono::Local).format("%d %b %H:%M:%S")),
            Cell::new(verdict_text(a.verdict)).fg(verdict_color(a.verdict)),
            Cell::new(a.identity.short()).fg(if a.identity.is_trusted_form() {
                Color::Reset
            } else {
                Color::Red
            }),
            Cell::new(
                a.files
                    .first()
                    .map(|f| {
                        f.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default()
                    })
                    .unwrap_or_default(),
            ),
            Cell::new(target_text(a)),
            Cell::new(match a.target() {
                Target::Net { bytes, .. } => human_bytes(bytes),
                _ => "–".to_string(),
            })
            .fg(Color::Yellow),
        ]);
    }
    println!("{t}");
}

fn print_alert(a: &Alert) {
    println!("{} #{}", "Alert".red().bold(), a.id);
    println!(
        "  time      {}",
        a.at.with_timezone(&chrono::Local)
            .format("%d %b %Y %H:%M:%S")
    );
    println!("  process   {} (pid {})", a.identity, a.pid);
    println!(
        "  verdict   {}{}",
        verdict_text(a.verdict),
        a.reason
            .as_deref()
            .map(|r| format!(": {r}"))
            .unwrap_or_default()
    );
    println!("  target    {}", target_text(a));
    println!("  sent      {}", human_bytes(a.bytes_out).yellow());
    if let Some(l) = a.last_at {
        println!(
            "  until     {} (total since the first report)",
            l.with_timezone(&chrono::Local).format("%d %b %Y %H:%M:%S")
        );
    }
    if let Some(v) = &a.via {
        println!("  via       {v}");
    }
    println!("  files:");
    for f in &a.files {
        println!("    {}", f.display());
    }
}

fn target_text(a: &Alert) -> String {
    match a.target() {
        Target::Volume(v) => format!("volume {}", v.display()),
        Target::Copy(d) => format!("copy to {}", d.display()),
        Target::Net { ip, port, .. } => format!("{ip}:{}", port.unwrap_or(0)),
        Target::Upload(u) => format!("upload to {u}"),
        Target::Unknown => "?".into(),
    }
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::New => "new",
        Verdict::Learning => "learning",
        Verdict::Deviation => "deviation",
        Verdict::Flagged => "flagged",
        Verdict::Denied => "denied",
        Verdict::Inbound => "inbound",
    }
}

fn verdict_color(v: Verdict) -> Color {
    match v {
        Verdict::Denied => Color::Magenta,
        Verdict::New | Verdict::Deviation => Color::Red,
        Verdict::Flagged => Color::Yellow,
        Verdict::Learning => Color::DarkGrey,
        // A notice, not an alarm: it says that something came in, not that
        // something got out.
        Verdict::Inbound => Color::Cyan,
    }
}

fn print_learn(st: &LearnStatus) {
    let phase = match st.phase {
        Phase::Learning => "learning phase".yellow().to_string(),
        Phase::Review => "review: check the list, then `deelpe learn confirm`"
            .red()
            .to_string(),
        Phase::Active => "active: only new and deviating traffic is reported"
            .green()
            .to_string(),
    };
    println!("{phase}");
    if let Some(u) = st.until {
        println!(
            "  learning phase until {}",
            u.with_timezone(&chrono::Local).format("%d %b %Y %H:%M")
        );
    }
    if st.pairs.is_empty() {
        println!("  No pairs.");
        return;
    }
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(["state", "process", "target", "n", "max", "last seen", "key"]);
    for p in &st.pairs {
        let (state, color) = match p.state {
            PairState::Candidate => ("candidate", Color::Yellow),
            PairState::Known => ("known", Color::Green),
            PairState::Flagged => ("flagged", Color::Red),
        };
        t.add_row([
            Cell::new(state).fg(color),
            Cell::new(&p.process),
            Cell::new(format!("{}:{}", p.destination, p.port.unwrap_or(0))),
            Cell::new(p.count),
            Cell::new(human_bytes(p.bytes_max)),
            Cell::new(
                p.last_seen
                    .with_timezone(&chrono::Local)
                    .format("%d %b %H:%M"),
            ),
            Cell::new(&p.key).fg(Color::DarkGrey),
        ]);
    }
    println!("{t}");
}

pub use deelpe_core::learn::human_bytes;

fn human_secs(s: u64) -> String {
    let (h, m) = (s / 3600, (s % 3600) / 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {}s", s % 60)
    }
}
