//! The open-source server: the library with nothing added.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    deelpe_server::run(deelpe_server::Extension::default()).await
}
