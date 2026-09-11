//! Local log of an agent — a file on the device and a ring of the most
//! recent lines, which go to the central server with the next report.
//!
//! Both together, because either one alone is too little: the file
//! survives a disruption of the line, but is only read by whoever sits
//! down at the device; otherwise the dashboard says nothing but "offline
//! since 14:03" and nobody knows why. So the ring keeps a record of what
//! happened during the disruption and sends it on as soon as the central
//! server answers again.
//!
//! The ring is explicitly lossy: if it overflows, the oldest entry drops
//! out. The complete record is in the file; the central server gets what
//! fits into a disruption of a few minutes.

use crate::central::LogLine;
use chrono::Utc;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// The ring holds this many lines.
const RING: usize = 1_000;
/// From this size on, the file moves aside once (`.1`). Two files, no
/// more: an agent must not fill up the customer's disk.
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// At most this many lines go out with one report.
pub const PER_REPORT: usize = 200;

struct Ring {
    /// Number of the oldest line in the ring.
    first: u64,
    lines: VecDeque<LogLine>,
}

fn ring() -> &'static Mutex<Ring> {
    static R: OnceLock<Mutex<Ring>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Ring { first: 0, lines: VecDeque::new() }))
}

fn push(line: LogLine) {
    let mut r = ring().lock().unwrap_or_else(|e| e.into_inner());
    r.lines.push_back(line);
    while r.lines.len() > RING {
        r.lines.pop_front();
        r.first += 1;
    }
}

/// Lines from number `seq` on, at most [`PER_REPORT`]. What also comes
/// back is the number to carry on from — the caller adopts that one only
/// **once the central server has accepted the report**. Otherwise the
/// lines of a failed transmission would be gone, and those are exactly
/// the ones that explain why it failed.
///
/// If the ring has moved on in the meantime, it starts at the oldest
/// entry: better a gap than nothing.
pub fn since(seq: u64) -> (u64, Vec<LogLine>) {
    let r = ring().lock().unwrap_or_else(|e| e.into_inner());
    let start = seq.max(r.first);
    let skip = (start - r.first) as usize;
    let lines: Vec<LogLine> = r.lines.iter().skip(skip).take(PER_REPORT).cloned().collect();
    (start + lines.len() as u64, lines)
}

/// Set up logging: ring always, file if a path is given, console on
/// request (a service has none). A second call is silently without effect
/// — there is only one global receiver.
pub fn init(path: Option<&Path>, console: bool) {
    // `info` as the default, which `RUST_LOG` refines instead of replacing:
    // whoever puts one module on `debug` does not want to lose the rest.
    let filter = EnvFilter::builder().with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into()).from_env_lossy();
    let file = path.and_then(|p| {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Without a file, better to keep running without one than not to
        // start at all.
        open(p).ok().map(Mutex::new)
    });
    let sink = Sink { file, path: path.map(Path::to_path_buf).unwrap_or_default() };
    let reg = tracing_subscriber::registry().with(filter).with(sink);
    if console {
        // Without module names: those are in the file, the console should
        // stay readable.
        let _ = reg.with(tracing_subscriber::fmt::layer().with_target(false)).try_init();
    } else {
        let _ = reg.try_init();
    }
}

fn open(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

struct Sink {
    file: Option<Mutex<std::fs::File>>,
    path: PathBuf,
}

impl Sink {
    fn write(&self, l: &LogLine) {
        let Some(f) = &self.file else { return };
        let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
        // Without colour codes: otherwise they sit in the log as control
        // characters.
        let _ = writeln!(f, "{} {:<5} {} {}", l.at.format("%Y-%m-%d %H:%M:%S%.3f"), l.level.to_uppercase(), l.target, l.msg);
        if f.metadata().map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
            let old = self.path.with_extension("log.1");
            // Windows does not rename over an existing file.
            let _ = std::fs::remove_file(&old);
            if std::fs::rename(&self.path, &old).is_ok() {
                if let Ok(new) = open(&self.path) {
                    *f = new;
                }
            }
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for Sink {
    fn on_event(&self, ev: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut text = Text(String::new());
        ev.record(&mut text);
        let m = ev.metadata();
        let line = LogLine { at: Utc::now(), level: m.level().as_str().to_ascii_lowercase(), target: m.target().to_string(), msg: text.0 };
        self.write(&line);
        push(line);
    }
}

/// The fields of an event turned into one line: the message bare,
/// everything else as `name=wert`.
struct Text(String);

impl Text {
    fn sep(&mut self) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
    }
}

impl tracing::field::Visit for Text {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.sep();
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            let _ = write!(self.0, "{}={value}", field.name());
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.sep();
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(msg: &str) -> LogLine {
        LogLine { at: Utc::now(), level: "info".into(), target: "t".into(), msg: msg.into() }
    }

    /// The contract of the loop: first fetch, send, and **then** adopt the
    /// number. Whoever adopts it too early loses exactly the lines of the
    /// failed transmission.
    ///
    /// One test, not three: the ring is global, concurrent tests would slip
    /// each other's lines in.
    #[test]
    fn ring_resends_until_accepted_and_survives_overflow() {
        for i in 0..3 {
            push(line(&format!("a{i}")));
        }
        let (next, first) = since(0);
        assert_eq!(first.len(), 3);
        // Report failed: the same lines once more.
        let (_, again) = since(0);
        assert_eq!(again.len(), 3);
        // Accepted: from here on only new material.
        let (_, none) = since(next);
        assert!(none.is_empty());
        push(line("b"));
        let (_, more) = since(next);
        assert_eq!(more.len(), 1);
        assert_eq!(more[0].msg, "b");

        // If the ring overflows, it starts at the oldest entry instead of
        // pointing into the void: a gap is acceptable, a crash is not.
        for i in 0..RING + 50 {
            push(line(&format!("x{i}")));
        }
        let (_, lines) = since(0);
        assert_eq!(lines.len(), PER_REPORT);
        assert!(lines[0].msg.starts_with('x'), "die aeltesten Zeilen sind weg: {}", lines[0].msg);
        let r = ring().lock().unwrap();
        assert!(r.first > 0, "der Ring muss weitergelaufen sein");
        assert_eq!(r.lines.len(), RING);
    }
}
