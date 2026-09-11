//! One listener loop for both ports. With a TLS configuration every
//! connection is negotiated and a client certificate, where there is one,
//! is put into the request as [`PeerCert`]; without it, it runs as HTTP
//! (dashboard behind a reverse proxy).

use crate::state::{PeerAddr, PeerCert};
use anyhow::Result;
use axum::Router;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tracing::{debug, info};

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
            let tls = acc.accept(stream).await?;
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
    let builder = Builder::new(TokioExecutor::new());
    let conn = builder.serve_connection_with_upgrades(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => r.map_err(|e| anyhow::anyhow!("{e}")),
        _ = stop.cancelled() => { conn.as_mut().graceful_shutdown(); conn.await.map_err(|e| anyhow::anyhow!("{e}")) }
    }
}
