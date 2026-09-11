// rust-embed needs `ui-dist/` at compile time. Without a built user
// interface (apps/web, `npm run build`) there is a placeholder, so that
// `cargo build` works from a fresh checkout.
fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui-dist");
    if !dir.join("index.html").exists() {
        std::fs::create_dir_all(&dir).expect("ui-dist");
        std::fs::write(
            dir.join("index.html"),
            "<!doctype html><meta charset=\"utf-8\"><title>DLPrevent</title><p>User interface not built: run <code>npm ci &amp;&amp; npm run build</code> in <code>apps/web</code>, then rebuild the server.</p>\n",
        )
        .expect("placeholder");
    }
    println!("cargo:rerun-if-changed=ui-dist");
}
