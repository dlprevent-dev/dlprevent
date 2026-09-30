//! One listener loop for both ports. With a TLS configuration every
//! connection is negotiated and a client certificate, where there is one,
//! is put into the request as [`PeerCert`]; without it, it runs as HTTP
//! (dashboard behind a reverse proxy).

use crate::state::{PeerAddr, PeerCert};
use anyhow::Result;
use axum::Router;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tracing::{debug, info};

/// A client that has not finished the TLS handshake by then is dropped.
/// Without a deadline every silent socket held a task and a file descriptor
/// for good. The HTTP headers get hyper's own 30 seconds, which only count
/// once the builder has a timer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(addr: SocketAddr, tls: Option<Arc<ServerConfig>>, router: Router, stop: CancellationToken) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, tls = tls.is_some(), "listening");
    let acceptor = tls.map(TlsAcceptor::from);
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => r?,
            _ = stop.cancelled() => return Ok(()),
        };
        let router = router.clone();
        let acceptor = acceptor.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, acceptor, router, stop).await {
                debug!(%peer, "Verbindung: {e}");
            }
        });
    }
}

async fn handle(stream: TcpStream, peer: SocketAddr, acceptor: Option<TlsAcceptor>, router: Router, stop: CancellationToken) -> Result<()> {
    let _ = stream.set_nodelay(true);
    match acceptor {
        Some(acc) => {
            let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acc.accept(stream)).await.map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
            let cert = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| PeerCert(crate::pki::fingerprint(c)));
            run(TokioIo::new(tls), peer, cert, router, stop).await
        }
        None => run(TokioIo::new(stream), peer, None, router, stop).await,
    }
}

async fn run<I>(io: I, peer: SocketAddr, cert: Option<PeerCert>, router: Router, stop: CancellationToken) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        let router = router.clone();
        req.extensions_mut().insert(PeerAddr(peer));
        if let Some(c) = &cert {
            req.extensions_mut().insert(c.clone());
        }
        async move { router.oneshot(req).await }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new());
    let conn = builder.serve_connection_with_upgrades(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => r.map_err(|e| anyhow::anyhow!("{e}")),
        _ = stop.cancelled() => { conn.as_mut().graceful_shutdown(); conn.await.map_err(|e| anyhow::anyhow!("{e}")) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use uuid::Uuid;

    async fn pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        (client, server, peer)
    }

    /// A client that opens the connection and never says hello held a task
    /// and a file descriptor for as long as it liked; a few thousand of them
    /// and neither agents nor the dashboard got in.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_finishes_the_handshake_is_dropped() {
        let dir = std::env::temp_dir().join(format!("deelpe-tls-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        let (_client, server, peer) = pair().await;
        let acc = Some(TlsAcceptor::from(pki.ui_config.clone()));
        let r = tokio::time::timeout(Duration::from_secs(300), handle(server, peer, acc, Router::new(), CancellationToken::new())).await;
        assert!(r.expect("the handshake still waits after five minutes").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Slowloris: the request line arrives, the headers never do.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_finishes_its_headers_is_dropped() {
        let (mut client, server, peer) = pair().await;
        client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(300), handle(server, peer, None, Router::new(), CancellationToken::new())).await;
        assert!(r.is_ok(), "the headers are still awaited after five minutes");
    }
}
