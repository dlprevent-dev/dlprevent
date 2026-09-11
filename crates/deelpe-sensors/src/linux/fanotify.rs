//! M3: file access via fanotify (kernel ≥ 5.1). Not implemented yet.
use crate::Sensor;
use async_trait::async_trait;
use deelpe_core::event::Event;
use tokio::sync::mpsc;

#[derive(Default)]
pub struct Fanotify;

#[async_trait]
impl Sensor for Fanotify {
    fn name(&self) -> &'static str {
        "fanotify"
    }
    async fn run(self: Box<Self>, _tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
        anyhow::bail!("the fanotify sensor lands in M3")
    }
}
