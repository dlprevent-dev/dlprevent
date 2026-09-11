//! M3: per-process connections via /proc/net + socket inodes. Not
//! implemented yet.
use crate::Sensor;
use async_trait::async_trait;
use deelpe_core::event::Event;
use tokio::sync::mpsc;

pub struct ProcNet {
    _interval: u64,
}

impl ProcNet {
    pub fn new(secs: u64) -> Self {
        Self { _interval: secs }
    }
}

#[async_trait]
impl Sensor for ProcNet {
    fn name(&self) -> &'static str {
        "procnet"
    }
    async fn run(self: Box<Self>, _tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
        anyhow::bail!("procnet-Sensor kommt in M3")
    }
}
