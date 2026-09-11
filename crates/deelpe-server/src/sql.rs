//! A query text that counts its own placeholders.
//!
//! Before, the caller worked them out — `terms.len()` plus a fixed number
//! plus an offset, in three places, with a constant that had to fit all
//! three of them. That made the binding order part of the interface:
//! whoever added a filter had to pull the constant and three offsets along
//! after it, and nothing checked that. A slipped placeholder silently binds
//! the wrong value — in bulk closing, for instance, a user identifier as a
//! search term.
//!
//! Now booking a value returns the placeholder under which it gets bound.
//! Text and binding can no longer drift apart, because they come out of the
//! same call.

use sqlx::postgres::PgArguments;
use sqlx::query::{Query, QueryAs};
use sqlx::Postgres;
use uuid::Uuid;

/// A value in binding order. Deliberately a small, closed list: what the
/// API binds are filters and limits, nothing exotic.
#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Bool(Option<bool>),
    Text(Option<String>),
    Uuid(Option<Uuid>),
    I64(i64),
    I64Opt(Option<i64>),
}

#[derive(Debug, Default)]
pub struct Binder(Vec<Arg>);

impl Binder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Book a value; back comes its placeholder (`$3`).
    pub fn push(&mut self, a: Arg) -> String {
        self.0.push(a);
        format!("${}", self.0.len())
    }

    pub fn bool(&mut self, v: Option<bool>) -> String {
        self.push(Arg::Bool(v))
    }

    /// Empty text counts as "no filter": for a select box that is not set
    /// the dashboard sends `""`, not `null`.
    pub fn text(&mut self, v: Option<String>) -> String {
        self.push(Arg::Text(v.filter(|s| !s.is_empty())))
    }

    pub fn uuid(&mut self, v: Option<Uuid>) -> String {
        self.push(Arg::Uuid(v))
    }

    pub fn i64(&mut self, v: i64) -> String {
        self.push(Arg::I64(v))
    }

    /// A number that may also be absent — for `($n::bigint IS NULL OR ...)`.
    pub fn i64_opt(&mut self, v: Option<i64>) -> String {
        self.push(Arg::I64Opt(v))
    }

    /// Bind the booked values to a `query_as`, in the same order in which
    /// the placeholders were handed out.
    pub fn bind_as<'q, O>(self, mut q: QueryAs<'q, Postgres, O, PgArguments>) -> QueryAs<'q, Postgres, O, PgArguments> {
        for a in self.0 {
            q = match a {
                Arg::Bool(v) => q.bind(v),
                Arg::Text(v) => q.bind(v),
                Arg::Uuid(v) => q.bind(v),
                Arg::I64(v) => q.bind(v),
                Arg::I64Opt(v) => q.bind(v),
            };
        }
        q
    }

    /// The same for a `query` without result rows (UPDATE, DELETE).
    pub fn bind<'q>(self, mut q: Query<'q, Postgres, PgArguments>) -> Query<'q, Postgres, PgArguments> {
        for a in self.0 {
            q = match a {
                Arg::Bool(v) => q.bind(v),
                Arg::Text(v) => q.bind(v),
                Arg::Uuid(v) => q.bind(v),
                Arg::I64(v) => q.bind(v),
                Arg::I64Opt(v) => q.bind(v),
            };
        }
        q
    }
}

/// Ordering from a request, checked against a fixed list.
///
/// The name from the request **never** lands in the SQL, only the
/// expression stored here; everything unknown falls back to `id`. The
/// secondary key `id DESC` makes the order unambiguous, otherwise rows with
/// the same value wander back and forth between two pages.
///
/// Until 2026-09-08 this stood written out twice — in `api/alerts.rs` and
/// `api/audit.rs`, right down to two tests with the same name.
pub fn order_by(sort: Option<&str>, dir: Option<&str>, allow: &[(&str, &str)]) -> String {
    let col = allow.iter().find(|(name, _)| *name == sort.unwrap_or("id")).map(|(_, expr)| *expr).unwrap_or("id");
    let d = if dir == Some("asc") { "ASC" } else { "DESC" };
    if col == "id" {
        format!("id {d}")
    } else {
        format!("{col} {d}, id DESC")
    }
}

/// A list query: condition, full-text search, ordering, window.
///
/// The sequence stood written out twice, step for step identically
/// (`api/alerts.rs`, `api/audit.rs`). Up to this point a third list cost a
/// third transcription — and with it the opportunity to apply
/// `AssertSqlSafe` to a string that does hold a request value after all.
///
/// Here only what came back from [`Binder`] as a placeholder gets into the
/// text, plus names that the caller writes down as a literal itself.
pub struct ListQuery {
    b: Binder,
    cond: String,
}

impl Default for ListQuery {
    fn default() -> Self {
        Self { b: Binder::new(), cond: "true".into() }
    }
}

impl ListQuery {
    pub fn new() -> Self {
        Self::default()
    }

    /// For conditions that this resource formulates itself. The caller
    /// books its values here and gets the placeholders back.
    pub fn binder(&mut self) -> &mut Binder {
        &mut self.b
    }

    /// Append a finished condition with AND.
    pub fn and(&mut self, cond: impl AsRef<str>) {
        self.cond.push_str(" AND ");
        self.cond.push_str(cond.as_ref());
    }

    /// Search terms against the haystack. Every word has to occur.
    ///
    /// `haystack` is a literal of the caller, never a request value — the
    /// terms themselves go in as bound values.
    pub fn search(&mut self, haystack: &str, terms: &[String]) {
        for t in terms {
            let p = self.b.text(Some(t.clone()));
            self.cond.push_str(&format!(" AND {haystack} LIKE {p}"));
        }
    }

    /// Build the query and bind the booked values.
    ///
    /// `cols`, `table` and `order` are literals or come from [`order_by`];
    /// the window bounds go in as bound values.
    pub fn finish<'q, O>(
        mut self,
        cols: &str,
        table: &str,
        order: &str,
        limit: i64,
        offset: i64,
    ) -> QueryAs<'q, Postgres, O, PgArguments>
    where
        O: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let l = self.b.i64(limit);
        let o = self.b.i64(offset);
        let cond = &self.cond;
        let sql = format!("SELECT {cols} FROM {table} WHERE {cond} ORDER BY {order} LIMIT {l} OFFSET {o}");
        self.b.bind_as(sqlx::query_as::<_, O>(sqlx::AssertSqlSafe(sql)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: &[(&str, &str)] = &[("at", "coalesce(last_at, at)"), ("who", "lower(user_display)")];

    /// The name from the request must never land in the SQL.
    #[test]
    fn order_only_from_allowlist() {
        assert_eq!(order_by(Some("at"), Some("asc"), ALLOW), "coalesce(last_at, at) ASC, id DESC");
        assert_eq!(order_by(Some("who"), None, ALLOW), "lower(user_display) DESC, id DESC");
        // Unknown, empty, and an injection attempt: everything becomes `id`.
        assert_eq!(order_by(Some("bogus"), None, ALLOW), "id DESC");
        assert_eq!(order_by(None, Some("asc"), ALLOW), "id ASC");
        assert_eq!(order_by(Some("id; DROP TABLE alerts"), None, ALLOW), "id DESC");
    }

    /// The window bounds are bound, not written into the text — and behind
    /// the filters at that, so that the placeholders come out right.
    #[test]
    fn the_window_is_bound_after_the_filters() {
        let mut q = ListQuery::new();
        let p = q.binder().text(Some("gl".into()));
        assert_eq!(p, "$1");
        q.and(format!("origin = {p}"));
        q.search("haystack", &["%abc%".to_string()]);
        // $2 is the search term, $3/$4 are limit and offset.
        assert_eq!(q.b.0.len(), 2);
        let expected = [Arg::Text(Some("gl".into())), Arg::Text(Some("%abc%".into()))];
        assert_eq!(q.b.0, expected);
        assert!(q.cond.contains("origin = $1"));
        assert!(q.cond.contains("haystack LIKE $2"));
    }

    #[test]
    fn placeholders_count_up_in_binding_order() {
        let mut b = Binder::new();
        assert_eq!(b.bool(Some(true)), "$1");
        assert_eq!(b.text(Some("x".into())), "$2");
        assert_eq!(b.uuid(None), "$3");
        assert_eq!(b.i64(100), "$4");
        assert_eq!(b.0.len(), 4);
        assert_eq!(b.0[1], Arg::Text(Some("x".into())));
    }

    #[test]
    fn an_empty_filter_is_no_filter() {
        let mut b = Binder::new();
        b.text(Some(String::new()));
        b.text(None);
        b.text(Some("gl".into()));
        assert_eq!(b.0, [Arg::Text(None), Arg::Text(None), Arg::Text(Some("gl".into()))]);
    }
}
