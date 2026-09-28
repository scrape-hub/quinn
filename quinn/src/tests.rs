#![cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]

#[cfg(all(feature = "rustls-aws-lc-rs", not(feature = "rustls-ring")))]
use rustls::crypto::aws_lc_rs::default_provider;
#[cfg(feature = "rustls-ring")]
use rustls::crypto::ring::default_provider;

use std::{
    convert::TryInto,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str,
    sync::Arc,
};

use crate::runtime::TokioRuntime;
use crate::{Duration, Instant};
use bytes::Bytes;
use proto::{RandomConnectionIdGenerator, crypto::rustls::QuicClientConfig};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::runtime::{Builder, Runtime};
use tracing::{error_span, info};
use tracing_futures::Instrument as _;
use tracing_subscriber::EnvFilter;

use super::{ClientConfig, Endpoint, EndpointConfig, RecvStream, SendStream, TransportConfig};

#[test]
fn handshake_timeout() {
    let _guard = subscribe();
    let runtime = rt_threaded();
    let client = {
        let _guard = runtime.enter();
        Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap()
    };

    // Avoid NoRootAnchors error
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.into()).unwrap();

    let mut client_config = crate::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    const IDLE_TIMEOUT: Duration = Duration::from_millis(500);
    let mut transport_config = crate::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()))
        .initial_rtt(Duration::from_millis(10));
    client_config.transport_config(Arc::new(transport_config));

    let start = Instant::now();
    runtime.block_on(async move {
        match client
            .connect_with(
                client_config,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                "localhost",
            )
            .unwrap()
            .await
        {
            Err(crate::ConnectionError::TimedOut) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
            Ok(_) => panic!("unexpected success"),
        }
    });
    let dt = start.elapsed();
    assert!(dt > IDLE_TIMEOUT && dt < 2 * IDLE_TIMEOUT);
}

#[tokio::test]
async fn close_endpoint() {
    let _guard = subscribe();

    // Avoid NoRootAnchors error
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.into()).unwrap();

    let mut endpoint =
        Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    endpoint
        .set_default_client_config(ClientConfig::with_root_certificates(Arc::new(roots)).unwrap());

    let conn = endpoint
        .connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            "localhost",
        )
        .unwrap();

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let conn = endpoint
        .connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            "localhost",
        )
        .unwrap();
    endpoint.close(0u32.into(), &[]);
    match conn.await {
        Err(crate::ConnectionError::LocallyClosed) => (),
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => {
            panic!("unexpected success");
        }
    }
}

#[test]
fn local_addr() {
    let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    let runtime = rt_basic();
    let ep = {
        let _guard = runtime.enter();
        Endpoint::new(Default::default(), None, socket, Arc::new(TokioRuntime)).unwrap()
    };
    assert_eq!(
        addr,
        ep.local_addr()
            .expect("Could not obtain our local endpoint")
    );
}

#[test]
fn read_after_close() {
    let _guard = subscribe();
    let runtime = rt_basic();
    let endpoint = {
        let _guard = runtime.enter();
        endpoint()
    };

    const MSG: &[u8] = b"goodbye!";
    let endpoint2 = endpoint.clone();
    runtime.spawn(async move {
        let new_conn = endpoint2
            .accept()
            .await
            .expect("endpoint")
            .await
            .expect("connection");
        let mut s = new_conn.open_uni().await.unwrap();
        s.write_all(MSG).await.unwrap();
        s.finish().unwrap();
        // Wait for the stream to be closed, one way or another.
        _ = s.stopped().await;
    });
    runtime.block_on(async move {
        let new_conn = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut stream = new_conn.accept_uni().await.expect("incoming streams");
        let msg = stream.read_to_end(usize::MAX).await.expect("read_to_end");
        assert_eq!(msg, MSG);
    });
}

#[test]
fn export_keying_material() {
    let _guard = subscribe();
    let runtime = rt_basic();
    let endpoint = {
        let _guard = runtime.enter();
        endpoint()
    };

    runtime.block_on(async move {
        let outgoing_conn_fut = tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost")
                    .unwrap()
                    .await
                    .expect("connect")
            }
        });
        let incoming_conn_fut = tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                endpoint
                    .accept()
                    .await
                    .expect("endpoint")
                    .await
                    .expect("connection")
            }
        });
        let outgoing_conn = outgoing_conn_fut.await.unwrap();
        let incoming_conn = incoming_conn_fut.await.unwrap();
        let mut i_buf = [0u8; 64];
        incoming_conn
            .export_keying_material(&mut i_buf, b"asdf", b"qwer")
            .unwrap();
        let mut o_buf = [0u8; 64];
        outgoing_conn
            .export_keying_material(&mut o_buf, b"asdf", b"qwer")
            .unwrap();
        assert_eq!(&i_buf[..], &o_buf[..]);
    });
}

#[tokio::test]
async fn ip_blocking() {
    let _guard = subscribe();
    let endpoint_factory = EndpointFactory::new();
    let client_1 = endpoint_factory.endpoint();
    let client_1_addr = client_1.local_addr().unwrap();
    let client_2 = endpoint_factory.endpoint();
    let server = endpoint_factory.endpoint();
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        loop {
            let accepting = server.accept().await.unwrap();
            if accepting.remote_address() == client_1_addr {
                accepting.refuse();
            } else if accepting.remote_address_validated() {
                accepting.await.expect("connection");
            } else {
                accepting.retry().unwrap();
            }
        }
    });
    tokio::join!(
        async move {
            let e = client_1
                .connect(server_addr, "localhost")
                .unwrap()
                .await
                .expect_err("server should have blocked this");
            assert!(
                matches!(e, crate::ConnectionError::ConnectionClosed(_)),
                "wrong error"
            );
        },
        async move {
            client_2
                .connect(server_addr, "localhost")
                .unwrap()
                .await
                .expect("connect");
        }
    );
    server_task.abort();
}

/// Construct an endpoint suitable for connecting to itself
fn endpoint() -> Endpoint {
    EndpointFactory::new().endpoint()
}

fn endpoint_with_config(transport_config: TransportConfig) -> Endpoint {
    EndpointFactory::new().endpoint_with_config(transport_config)
}

/// Constructs endpoints suitable for connecting to themselves and each other
struct EndpointFactory {
    cert: rcgen::CertifiedKey<rcgen::KeyPair>,
    endpoint_config: EndpointConfig,
}

impl EndpointFactory {
    fn new() -> Self {
        Self {
            cert: rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap(),
            endpoint_config: EndpointConfig::default(),
        }
    }

    fn endpoint(&self) -> Endpoint {
        self.endpoint_with_config(TransportConfig::default())
    }

    fn endpoint_with_config(&self, transport_config: TransportConfig) -> Endpoint {
        let key = PrivateKeyDer::Pkcs8(self.cert.signing_key.serialize_der().into());
        let transport_config = Arc::new(transport_config);
        let mut server_config =
            crate::ServerConfig::with_single_cert(vec![self.cert.cert.der().clone()], key).unwrap();
        server_config.transport_config(transport_config.clone());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.cert.der().clone()).unwrap();
        let mut endpoint = Endpoint::new(
            self.endpoint_config.clone(),
            Some(server_config),
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap(),
            Arc::new(TokioRuntime),
        )
        .unwrap();
        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config.transport_config(transport_config);
        endpoint.set_default_client_config(client_config);

        endpoint
    }
}

#[tokio::test]
async fn zero_rtt() {
    let _guard = subscribe();
    let endpoint = endpoint();

    const MSG0: &[u8] = b"zero";
    const MSG1: &[u8] = b"one";
    let endpoint2 = endpoint.clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = endpoint2.accept().await.unwrap().accept().unwrap();
            let (connection, established) = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
            let c = connection.clone();
            tokio::spawn(async move {
                while let Ok(mut x) = c.accept_uni().await {
                    let msg = x.read_to_end(usize::MAX).await.unwrap();
                    assert_eq!(msg, MSG0);
                }
            });
            info!("sending 0.5-RTT");
            let mut s = connection.open_uni().await.expect("open_uni");
            s.write_all(MSG0).await.expect("write");
            s.finish().unwrap();
            established.await;
            info!("sending 1-RTT");
            let mut s = connection.open_uni().await.expect("open_uni");
            s.write_all(MSG1).await.expect("write");
            // The peer might close the connection before ACKing
            let _ = s.finish();
        }
    });

    let connection = endpoint
        .connect(endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .err()
        .expect("0-RTT succeeded without keys")
        .await
        .expect("connect");

    {
        let mut stream = connection.accept_uni().await.expect("incoming streams");
        let msg = stream.read_to_end(usize::MAX).await.expect("read_to_end");
        assert_eq!(msg, MSG0);
        // Read a 1-RTT message to ensure the handshake completes fully, allowing the server's
        // NewSessionTicket frame to be received.
        let mut stream = connection.accept_uni().await.expect("incoming streams");
        let msg = stream.read_to_end(usize::MAX).await.expect("read_to_end");
        assert_eq!(msg, MSG1);
        drop(connection);
    }

    info!("initial connection complete");

    let (connection, zero_rtt) = endpoint
        .connect(endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("missing 0-RTT keys"));
    // Send something ASAP to use 0-RTT
    let c = connection.clone();
    tokio::spawn(async move {
        let mut s = c.open_uni().await.expect("0-RTT open uni");
        info!("sending 0-RTT");
        s.write_all(MSG0).await.expect("0-RTT write");
        s.finish().unwrap();
    });

    let mut stream = connection.accept_uni().await.expect("incoming streams");
    let msg = stream.read_to_end(usize::MAX).await.expect("read_to_end");
    assert_eq!(msg, MSG0);
    assert!(zero_rtt.await);

    drop((stream, connection));

    endpoint.wait_idle().await;
}

#[test]
#[cfg_attr(
    any(target_os = "solaris", target_os = "illumos"),
    ignore = "Fails on Solaris and Illumos"
)]
fn echo_v6() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        nr_streams: 1,
        stream_size: 10 * 1024,
        receive_window: None,
        stream_receive_window: None,
    });
}

#[test]
#[cfg_attr(target_os = "solaris", ignore = "Sometimes hangs in poll() on Solaris")]
fn echo_v4() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 1,
        stream_size: 10 * 1024,
        receive_window: None,
        stream_receive_window: None,
    });
}

#[test]
#[cfg_attr(target_os = "solaris", ignore = "Hangs in poll() on Solaris")]
fn echo_dualstack() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 1,
        stream_size: 10 * 1024,
        receive_window: None,
        stream_receive_window: None,
    });
}

#[test]
#[ignore]
#[cfg_attr(target_os = "solaris", ignore = "Hangs in poll() on Solaris")]
fn stress_receive_window() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 50,
        stream_size: 25 * 1024 + 11,
        receive_window: Some(37),
        stream_receive_window: Some(100 * 1024 * 1024),
    });
}

#[test]
#[ignore]
#[cfg_attr(target_os = "solaris", ignore = "Hangs in poll() on Solaris")]
fn stress_stream_receive_window() {
    // Note that there is no point in running this with too many streams,
    // since the window is only active within a stream.
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 2,
        stream_size: 250 * 1024 + 11,
        receive_window: Some(100 * 1024 * 1024),
        stream_receive_window: Some(37),
    });
}

#[test]
#[ignore]
#[cfg_attr(target_os = "solaris", ignore = "Hangs in poll() on Solaris")]
fn stress_both_windows() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 50,
        stream_size: 25 * 1024 + 11,
        receive_window: Some(37),
        stream_receive_window: Some(37),
    });
}

fn run_echo(args: EchoArgs) {
    let _guard = subscribe();
    let runtime = rt_basic();
    let handle = {
        // Use small receive windows
        let mut transport_config = TransportConfig::default();
        if let Some(receive_window) = args.receive_window {
            transport_config.receive_window(receive_window.try_into().unwrap());
        }
        if let Some(stream_receive_window) = args.stream_receive_window {
            transport_config.stream_receive_window(stream_receive_window.try_into().unwrap());
        }
        transport_config.max_concurrent_bidi_streams(1_u8.into());
        transport_config.max_concurrent_uni_streams(1_u8.into());
        let transport_config = Arc::new(transport_config);

        // We don't use the `endpoint` helper here because we want two different endpoints with
        // different addresses.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let cert = CertificateDer::from(cert.cert);
        let mut server_config =
            crate::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();

        server_config.transport = transport_config.clone();
        let server_sock = UdpSocket::bind(args.server_addr).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let server = {
            let _guard = runtime.enter();
            let _guard = error_span!("server").entered();
            Endpoint::new(
                Default::default(),
                Some(server_config),
                server_sock,
                Arc::new(TokioRuntime),
            )
            .unwrap()
        };

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client_crypto =
            rustls::ClientConfig::builder_with_provider(default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

        let mut client = {
            let _guard = runtime.enter();
            let _guard = error_span!("client").entered();
            Endpoint::client(args.client_addr).unwrap()
        };
        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        client_config.transport_config(transport_config);
        client.set_default_client_config(client_config);

        let handle = runtime.spawn(async move {
            let incoming = server.accept().await.unwrap();

            // Note for anyone modifying the platform support in this test:
            // If `local_ip` gets available on additional platforms - which
            // requires modifying this test - please update the list of supported
            // platforms in the doc comment of `quinn_udp::RecvMeta::dst_ip`.
            if cfg!(target_os = "linux")
                || cfg!(target_os = "android")
                || cfg!(target_os = "freebsd")
                || cfg!(target_os = "openbsd")
                || cfg!(target_os = "netbsd")
                || cfg!(target_os = "macos")
                || cfg!(target_os = "windows")
            {
                let local_ip = incoming.local_ip().expect("Local IP must be available");
                assert!(local_ip.is_loopback());
            } else {
                assert_eq!(None, incoming.local_ip());
            }

            let new_conn = incoming.await.unwrap();
            tokio::spawn(async move {
                while let Ok(stream) = new_conn.accept_bi().await {
                    tokio::spawn(echo(stream));
                }
            });
            server.wait_idle().await;
        });

        info!("connecting from {} to {}", args.client_addr, server_addr);
        runtime.block_on(
            async move {
                let new_conn = client
                    .connect(server_addr, "localhost")
                    .unwrap()
                    .await
                    .expect("connect");

                /// This is just an arbitrary number to generate deterministic test data
                const SEED: u64 = 0x12345678;

                for i in 0..args.nr_streams {
                    println!("Opening stream {i}");
                    let (mut send, mut recv) = new_conn.open_bi().await.expect("stream open");
                    let msg = gen_data(args.stream_size, SEED);

                    let send_task = async {
                        send.write_all(&msg).await.expect("write");
                        send.finish().unwrap();
                    };
                    let recv_task = async { recv.read_to_end(usize::MAX).await.expect("read") };

                    let (_, data) = tokio::join!(send_task, recv_task);

                    assert_eq!(data[..], msg[..], "Data mismatch");
                }
                new_conn.close(0u32.into(), b"done");
                client.wait_idle().await;
            }
            .instrument(error_span!("client")),
        );
        handle
    };
    runtime.block_on(handle).unwrap();
}

struct EchoArgs {
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    nr_streams: usize,
    stream_size: usize,
    receive_window: Option<u64>,
    stream_receive_window: Option<u64>,
}

async fn echo((mut send, mut recv): (SendStream, RecvStream)) {
    loop {
        // These are 32 buffers, for reading approximately 32kB at once
        #[rustfmt::skip]
        let mut bufs = [
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        ];

        match recv.read_chunks(&mut bufs).await.expect("read chunks") {
            Some(n) => {
                send.write_all_chunks(&mut bufs[..n])
                    .await
                    .expect("write chunks");
            }
            None => break,
        }
    }

    let _ = send.finish();
}

fn gen_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
    let mut buf = vec![0; size];
    rng.fill_bytes(&mut buf);
    buf
}

fn subscribe() -> tracing::subscriber::DefaultGuard {
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(|| TestWriter)
        .finish();
    tracing::subscriber::set_default(sub)
}

struct TestWriter;

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

fn rt_basic() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn rt_threaded() -> Runtime {
    Builder::new_multi_thread().enable_all().build().unwrap()
}

#[tokio::test]
async fn rebind_recv() {
    let _guard = subscribe();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();

    let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(Arc::new({
        let mut cfg = TransportConfig::default();
        cfg.max_concurrent_uni_streams(1u32.into());
        cfg
    }));
    client.set_default_client_config(client_config);

    let server_config =
        crate::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
    let server = {
        let _guard = tracing::error_span!("server").entered();
        Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap()
    };
    let server_addr = server.local_addr().unwrap();

    const MSG: &[u8; 5] = b"hello";

    let write_send = Arc::new(tokio::sync::Notify::new());
    let write_recv = write_send.clone();
    let connected_send = Arc::new(tokio::sync::Notify::new());
    let connected_recv = connected_send.clone();
    let server = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        info!("got conn");
        connected_send.notify_one();
        write_recv.notified().await;
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(MSG).await.unwrap();
        stream.finish().unwrap();
        // Wait for the stream to be closed, one way or another.
        _ = stream.stopped().await;
    });

    let connection = {
        let _guard = tracing::error_span!("client").entered();
        client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    };
    info!("connected");
    connected_recv.notified().await;
    client
        .rebind(UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap())
        .unwrap();
    info!("rebound");
    write_send.notify_one();
    let mut stream = connection.accept_uni().await.unwrap();
    assert_eq!(stream.read_to_end(MSG.len()).await.unwrap(), MSG);
    server.await.unwrap();
}

#[tokio::test]
async fn stream_id_flow_control() {
    let _guard = subscribe();
    let mut cfg = TransportConfig::default();
    cfg.max_concurrent_uni_streams(1u32.into());
    let endpoint = endpoint_with_config(cfg);

    let (client, server) = tokio::join!(
        endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { endpoint.accept().await.unwrap().await }
    );
    let client = client.unwrap();
    let server = server.unwrap();

    // If `open_uni` doesn't get unblocked when the previous stream is dropped, this will time out.
    tokio::join!(
        async {
            client.open_uni().await.unwrap();
        },
        async {
            client.open_uni().await.unwrap();
        },
        async {
            client.open_uni().await.unwrap();
        },
        async {
            server.accept_uni().await.unwrap();
            server.accept_uni().await.unwrap();
        }
    );
}

#[tokio::test]
async fn two_datagram_readers() {
    let _guard = subscribe();
    let endpoint = endpoint();

    let (client, server) = tokio::join!(
        endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { endpoint.accept().await.unwrap().await }
    );
    let client = client.unwrap();
    let server = server.unwrap();

    let done = tokio::sync::Notify::new();
    let (a, b, ()) = tokio::join!(
        async {
            let x = client.read_datagram().await.unwrap();
            done.notify_waiters();
            x
        },
        async {
            let x = client.read_datagram().await.unwrap();
            done.notify_waiters();
            x
        },
        async {
            server.send_datagram(b"one"[..].into()).unwrap();
            done.notified().await;
            server.send_datagram_wait(b"two"[..].into()).await.unwrap();
        }
    );
    assert!(*a == *b"one" || *b == *b"one");
    assert!(*a == *b"two" || *b == *b"two");
}

#[tokio::test]
async fn multiple_conns_with_zero_length_cids() {
    let _guard = subscribe();
    let mut factory = EndpointFactory::new();
    factory
        .endpoint_config
        .cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)));
    let server = {
        let _guard = error_span!("server").entered();
        factory.endpoint()
    };
    let server_addr = server.local_addr().unwrap();

    let client1 = {
        let _guard = error_span!("client1").entered();
        factory.endpoint()
    };
    let client2 = {
        let _guard = error_span!("client2").entered();
        factory.endpoint()
    };

    let client1 = async move {
        let conn = client1
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        conn.closed().await;
    }
    .instrument(error_span!("client1"));
    let client2 = async move {
        let conn = client2
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        conn.closed().await;
    }
    .instrument(error_span!("client2"));
    let server = async move {
        let client1 = server.accept().await.unwrap().await.unwrap();
        let client2 = server.accept().await.unwrap().await.unwrap();
        // Both connections are now concurrently live.
        client1.close(42u32.into(), &[]);
        client2.close(42u32.into(), &[]);
    }
    .instrument(error_span!("server"));
    tokio::join!(client1, client2, server);
}

#[tokio::test]
async fn stream_stopped() {
    let _guard = subscribe();
    let factory = EndpointFactory::new();
    let server = {
        let _guard = error_span!("server").entered();
        factory.endpoint()
    };
    let server_addr = server.local_addr().unwrap();

    let client = {
        let _guard = error_span!("client1").entered();
        factory.endpoint()
    };

    let client = async move {
        let conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut stream = conn.open_uni().await.unwrap();
        let stopped1 = stream.stopped();
        let stopped2 = stream.stopped();
        let stopped3 = stream.stopped();

        stream.write_all(b"hi").await.unwrap();
        // spawn one of the futures into a task
        let stopped1 = tokio::task::spawn(stopped1);
        // verify that both futures resolved
        let (stopped1, stopped2) = tokio::join!(stopped1, stopped2);
        assert!(matches!(stopped1, Ok(Ok(Some(val))) if val == 42u32.into()));
        assert!(matches!(stopped2, Ok(Some(val)) if val == 42u32.into()));
        // drop the stream
        drop(stream);
        // verify that a future also resolves after dropping the stream
        let stopped3 = stopped3.await;
        assert_eq!(stopped3, Ok(Some(42u32.into())));
    };
    let client =
        tokio::time::timeout(Duration::from_millis(100), client).instrument(error_span!("client"));
    let server = async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut stream = conn.accept_uni().await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        stream.stop(42u32.into()).unwrap();
        conn
    }
    .instrument(error_span!("server"));
    let (client, conn) = tokio::join!(client, server);
    client.expect("timeout");
    drop(conn);
}

#[tokio::test]
async fn stream_stopped_2() {
    let _guard = subscribe();
    let endpoint = endpoint();

    let (conn, _server_conn) = tokio::try_join!(
        endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { endpoint.accept().await.unwrap().await }
    )
    .unwrap();
    let send_stream = conn.open_uni().await.unwrap();
    let stopped = tokio::time::timeout(Duration::from_millis(100), send_stream.stopped())
        .instrument(error_span!("stopped"));
    tokio::pin!(stopped);
    // poll the future once so that the waker is registered.
    tokio::select! {
        biased;
        _x = &mut stopped => {},
        _x = std::future::ready(()) => {}
    }
    // drop the send stream
    drop(send_stream);
    // make sure the stopped future still resolves
    let res = stopped.await;
    assert_eq!(res, Ok(Ok(None)));
}

/// Transport and endpoint settings with the wire behaviour of Chrome (`chrome`) or Firefox
///
/// Only the options that change how packets are sent; the transport parameters are covered by
/// quinn-proto's tests.
fn browser_like(chrome: bool) -> (TransportConfig, EndpointConfig) {
    let mut fingerprint = crate::FingerprintConfig::default();
    fingerprint
        .early_key_update(false)
        .ack_each_datagram(true)
        .trailing_ping(true);
    let (cid_len, mtu) = match chrome {
        true => {
            fingerprint
                .packet_numbering(crate::PacketNumbering::Shared { first: 1 })
                .initial_padding(crate::InitialPadding::Frames { size: 1250 })
                .crypto_framing(crate::CryptoFraming::ChaosProtection)
                .spin_bit(crate::SpinBit::Zero)
                .ack_decimation(Some(crate::AckDecimation::default()))
                .ack_policy(crate::AckPolicy::Quiche)
                .packet_padding(crate::PacketPadding::Leading)
                .buffered_packet_processing(crate::BufferedPacketProcessing::AfterFirst1rttData);
            (0, 1250)
        }
        false => {
            fingerprint
                .packet_numbering(crate::PacketNumbering::Sequential {
                    first_initial: crate::FirstPacketNumber::Fixed(321),
                })
                .initial_padding(crate::InitialPadding::TrailingZeros { size: 1252 })
                .crypto_framing(crate::CryptoFraming::SniSlicing)
                .spin_bit(crate::SpinBit::Random)
                .early_connection_ids(true);
            (3, 1252)
        }
    };
    let mut transport = TransportConfig::default();
    transport
        .initial_mtu(mtu)
        .mtu_discovery_config(None)
        .fingerprint(fingerprint);
    let mut endpoint = EndpointConfig::default();
    endpoint
        .cid_generator(move || Box::new(RandomConnectionIdGenerator::new(cid_len)))
        .grease_quic_bit(false);
    (transport, endpoint)
}

/// Browser-like clients complete handshakes, transfers and 0-RTT resumption with a Quinn server
/// over real loopback sockets
#[tokio::test]
async fn browser_like_clients() {
    let _guard = subscribe();
    for (name, (transport, endpoint_config)) in [
        ("chrome", browser_like(true)),
        ("firefox", browser_like(false)),
    ] {
        info!(name, "testing browser-like client");
        let factory = EndpointFactory::new();
        let server = factory.endpoint();
        let server_addr = server.local_addr().unwrap();
        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                for _ in 0..2 {
                    let incoming = server.accept().await.unwrap().accept().unwrap();
                    let (connection, _) = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
                    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                    let request = recv.read_to_end(usize::MAX).await.unwrap();
                    assert_eq!(request, b"GET /");
                    send.write_all(&vec![0x42; 500_000]).await.unwrap();
                    send.finish().unwrap();
                    connection.closed().await;
                }
            })
        };

        let mut roots = rustls::RootCertStore::empty();
        roots.add(factory.cert.cert.der().clone()).unwrap();
        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config
            .transport_config(Arc::new(transport))
            .initial_dst_cid_provider(Arc::new(|| {
                use crate::ConnectionIdGenerator as _;
                RandomConnectionIdGenerator::new(8).generate_cid()
            }));
        let client = Endpoint::new(
            endpoint_config,
            None,
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap(),
            Arc::new(TokioRuntime),
        )
        .unwrap();

        async fn request(connection: &crate::Connection) {
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(b"GET /").await.unwrap();
            send.finish().unwrap();
            let response = recv.read_to_end(usize::MAX).await.unwrap();
            assert_eq!(response.len(), 500_000);
        }

        // Full handshake
        let connection = client
            .connect_with(client_config.clone(), server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        request(&connection).await;
        // A PING on the application's initiative, as Chrome sends them to keep a connection alive
        let pings = connection.stats().frame_tx.ping;
        connection.ping();
        tokio::time::timeout(Duration::from_secs(5), async {
            while connection.stats().frame_tx.ping == pings {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{name}: no PING sent"));
        connection.close(0u32.into(), b"done");

        // Resumption, with the request in 0-RTT
        let (connection, accepted) = client
            .connect_with(client_config, server_addr, "localhost")
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("{name}: missing 0-RTT keys"));
        request(&connection).await;
        assert!(accepted.await, "{name}: 0-RTT rejected");
        connection.close(0u32.into(), b"done");

        server_task.await.unwrap();
        client.wait_idle().await;
    }
}

/// A client session that verifies the server's certificate on another thread: the handshake data
/// after the ServerHello waits until a worker thread has slept for `delay` and woken the
/// connection
struct ThreadedSession {
    inner: Box<dyn proto::crypto::Session>,
    delay: Duration,
    handshake_keys: bool,
    held: Vec<Vec<u8>>,
    worker: Option<Worker>,
}

/// Whether the worker thread is done, and the waker to wake then
type Worker = Arc<std::sync::Mutex<(bool, Option<std::task::Waker>)>>;

struct ThreadedClientConfig {
    inner: Arc<QuicClientConfig>,
    delay: Duration,
}

impl proto::crypto::ClientConfig for ThreadedClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &proto::transport_parameters::TransportParameters,
    ) -> Result<Box<dyn proto::crypto::Session>, proto::ConnectError> {
        Ok(Box::new(ThreadedSession {
            inner: self
                .inner
                .clone()
                .start_session(version, server_name, params)?,
            delay: self.delay,
            handshake_keys: false,
            held: Vec::new(),
            worker: None,
        }))
    }
}

impl proto::crypto::Session for ThreadedSession {
    fn initial_keys(
        &self,
        dst_cid: &crate::ConnectionId,
        side: crate::Side,
    ) -> proto::crypto::Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(
        &self,
    ) -> Option<(
        Box<dyn proto::crypto::HeaderKey>,
        Box<dyn proto::crypto::PacketKey>,
    )> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, proto::TransportError> {
        if !self.handshake_keys {
            return self.inner.read_handshake(buf);
        }
        self.held.push(buf.to_vec());
        Ok(false)
    }

    fn poll_handshake(
        &mut self,
        waker: &std::task::Waker,
    ) -> std::task::Poll<Result<(), proto::TransportError>> {
        use std::task::Poll;
        if self.held.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let worker = self.worker.get_or_insert_with(|| {
            let state = Arc::new(std::sync::Mutex::new((false, None::<std::task::Waker>)));
            let shared = state.clone();
            let delay = self.delay;
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                let mut state = shared.lock().unwrap();
                state.0 = true;
                if let Some(waker) = state.1.take() {
                    waker.wake();
                }
            });
            state
        });
        {
            let mut state = worker.lock().unwrap();
            if !state.0 {
                state.1 = Some(waker.clone());
                return Poll::Pending;
            }
        }
        self.worker = None;
        for data in std::mem::take(&mut self.held) {
            self.inner.read_handshake(&data)?;
        }
        Poll::Ready(Ok(()))
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<proto::transport_parameters::TransportParameters>, proto::TransportError>
    {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<proto::crypto::Keys> {
        let keys = self.inner.write_handshake(buf);
        self.handshake_keys |= keys.is_some();
        keys
    }

    fn next_1rtt_keys(
        &mut self,
    ) -> Option<proto::crypto::KeyPair<Box<dyn proto::crypto::PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(
        &self,
        orig_dst_cid: &crate::ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), proto::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

/// A session that finishes the handshake on another thread wakes the connection driver, which
/// completes the handshake
#[tokio::test]
async fn async_certificate_verification() {
    let _guard = subscribe();
    let factory = EndpointFactory::new();
    let server = factory.endpoint();
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut send = connection.open_uni().await.unwrap();
        send.write_all(b"hello").await.unwrap();
        send.finish().unwrap();
        connection.closed().await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let client_crypto = rustls::ClientConfig::builder_with_provider(default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let delay = Duration::from_millis(20);
    let client_config = ClientConfig::new(Arc::new(ThreadedClientConfig {
        inner: Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()),
        delay,
    }));
    let client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let start = Instant::now();
    let connection = client
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    assert!(start.elapsed() >= delay);
    let mut recv = connection.accept_uni().await.unwrap();
    assert_eq!(recv.read_to_end(usize::MAX).await.unwrap(), b"hello");
    connection.close(0u32.into(), b"done");
    server_task.await.unwrap();
    client.wait_idle().await;
}

/// Writes made under a `TransmitHold` leave in one packet even on a multi-threaded runtime,
/// `write_all_and_finish` sends data and FIN in one STREAM frame, and `close_transport` reaches
/// the peer as a transport-level close
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batched_writes_and_transport_close() {
    const RUNS: usize = 30;
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport.mtu_discovery_config(None);
    let endpoint = EndpointFactory::new().endpoint_with_config(transport);
    let server_addr = endpoint.local_addr().unwrap();

    let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let server = endpoint.clone();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        // Keep the send halves so that the server sends nothing the client has to acknowledge
        let mut send_halves = Vec::new();
        for _ in 0..2 * RUNS + 1 {
            let (send, mut recv) = connection.accept_bi().await.unwrap();
            let request = recv.read_to_end(usize::MAX).await.unwrap();
            send_halves.push(send);
            requests_tx.send(request).unwrap();
        }
        connection.closed().await
    });

    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    // Long-lived unidirectional streams, like HTTP/3's control and QPACK encoder streams
    let mut control = connection.open_uni().await.unwrap();
    let mut encoder = connection.open_uni().await.unwrap();
    control.write_all(b"settings").await.unwrap();
    encoder.write_all(b"capacity").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut streams = Vec::new();
    for _ in 0..RUNS {
        let before = connection.stats();
        {
            let _hold = connection.hold_transmit();
            control.write_all(b"priority update").await.unwrap();
            encoder.write_all(b"insert").await.unwrap();
            let (mut send, recv) = connection.open_bi().await.unwrap();
            send.write_all(b"headers").await.unwrap();
            send.finish().unwrap();
            streams.push((send, recv));
        }
        assert_eq!(requests.recv().await.unwrap(), b"headers");
        let after = connection.stats();
        assert_eq!(after.frame_tx.stream - before.frame_tx.stream, 3);
        assert_eq!(after.udp_tx.datagrams - before.udp_tx.datagrams, 1);
    }

    for _ in 0..RUNS {
        let before = connection.stats();
        let (mut send, recv) = connection.open_bi().await.unwrap();
        send.write_all_and_finish(b"headers").await.unwrap();
        streams.push((send, recv));
        assert_eq!(requests.recv().await.unwrap(), b"headers");
        let after = connection.stats();
        assert_eq!(after.frame_tx.stream - before.frame_tx.stream, 1);
        assert_eq!(after.udp_tx.datagrams - before.udp_tx.datagrams, 1);
    }

    // A leaked hold delays transmission by at most 10 ms
    std::mem::forget(connection.hold_transmit());
    let (mut send, recv) = connection.open_bi().await.unwrap();
    send.write_all_and_finish(b"late").await.unwrap();
    streams.push((send, recv));
    let late = tokio::time::timeout(Duration::from_secs(1), requests.recv()).await;
    assert_eq!(late.unwrap().unwrap(), b"late");

    connection.close_transport(
        proto::TransportErrorCode::NO_ERROR,
        Some(crate::VarInt::from_u32(0)),
        b"70:net error",
    );
    match server_task.await.unwrap() {
        crate::ConnectionError::ConnectionClosed(close) => {
            assert_eq!(close.error_code, proto::TransportErrorCode::NO_ERROR);
            assert_eq!(&close.reason[..], b"70:net error");
        }
        e => panic!("unexpected close: {e}"),
    }
    endpoint.wait_idle().await;
}

/// An abandoned connection sends nothing: no `CONNECTION_CLOSE`, not when its last handle is
/// dropped, and not while its endpoint shuts down
#[tokio::test]
async fn abandon_sends_nothing() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let _guard = subscribe();
    let factory = EndpointFactory::new();
    let server = factory.endpoint();
    let server_addr = server.local_addr().unwrap();
    let client = factory.endpoint();

    // A relay between client and server counts the client's datagrams
    let relay = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay.local_addr().unwrap();
    let from_client = Arc::new(AtomicUsize::new(0));
    let relay_task = tokio::spawn({
        let from_client = from_client.clone();
        async move {
            let mut buf = vec![0; 65_536];
            let mut client_addr = None;
            loop {
                let (len, from) = relay.recv_from(&mut buf).await.unwrap();
                let to = match from == server_addr {
                    true => client_addr,
                    false => {
                        from_client.fetch_add(1, Relaxed);
                        client_addr = Some(from);
                        Some(server_addr)
                    }
                };
                if let Some(to) = to {
                    relay.send_to(&buf[..len], to).await.unwrap();
                }
            }
        }
    });

    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let (send, mut recv) = connection.accept_bi().await.unwrap();
        let mut buf = [0; 7];
        recv.read_exact(&mut buf).await.unwrap();
        (connection, send, recv)
    });
    let connection = client
        .connect(relay_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"request").await.unwrap();
    let (server_connection, _server_send, _server_recv) = server_task.await.unwrap();
    // Let the last acknowledgements pass
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sent = from_client.load(Relaxed);
    let tx = connection.stats().udp_tx.datagrams;

    connection.abandon();
    assert_eq!(
        connection.close_reason(),
        Some(crate::ConnectionError::LocallyClosed)
    );
    assert!(matches!(
        send.write_all(b"late").await,
        Err(crate::WriteError::ConnectionLost(
            crate::ConnectionError::LocallyClosed
        ))
    ));
    assert!(matches!(
        recv.read(&mut [0; 8]).await,
        Err(crate::ReadError::ConnectionLost(
            crate::ConnectionError::LocallyClosed
        ))
    ));
    assert_eq!(connection.stats().udp_tx.datagrams, tx);
    drop((send, recv, connection));
    // The endpoint forgets the connection at once
    tokio::time::timeout(Duration::from_secs(1), client.wait_idle())
        .await
        .unwrap();
    assert_eq!(client.open_connections(), 0);
    drop(client);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(from_client.load(Relaxed), sent);
    assert_eq!(server_connection.close_reason(), None);
    relay_task.abort();
}

/// A client that holds its Finished for the first application data gets its connection while the
/// Finished waits, and its first write releases it. The handshake is resumed without 0-RTT, as
/// with Cloudflare's session tickets, so that it completes as soon as the server's flight is
/// processed.
///
/// Depends on timing: the Finished waits at most 1 ms after the server's flight arrived, which a
/// busy machine exceeds before the application runs. Run it on its own with
/// `cargo test -p quinn --lib -- --ignored finished_waits_for_first_write`.
#[tokio::test]
#[ignore = "timing-dependent; see the documentation"]
async fn finished_waits_for_first_write() {
    let _guard = subscribe();
    for hold in [true, false] {
        let factory = EndpointFactory::new();
        let key = PrivateKeyDer::Pkcs8(factory.cert.signing_key.serialize_der().into());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![factory.cert.cert.der().clone()], key)
            .unwrap();
        tls.max_early_data_size = 0;
        let crypto = proto::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server = Endpoint::server(
            crate::ServerConfig::with_crypto(Arc::new(crypto)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let connection = server.accept().await.unwrap().await.unwrap();
                let mut recv = connection.accept_uni().await.unwrap();
                received.push(recv.read_to_end(usize::MAX).await.unwrap());
                connection.close(0u32.into(), b"done");
            }
            received
        });

        let mut fingerprint = crate::FingerprintConfig::default();
        fingerprint.finished_with_first_data(hold);
        let mut transport = TransportConfig::default();
        transport.fingerprint(fingerprint);
        let client = factory.endpoint_with_config(transport);
        for resumed in [false, true] {
            let connection = client
                .connect(server_addr, "localhost")
                .unwrap()
                .await
                .unwrap();
            // Only the ClientHello has been sent if the Finished waits
            let crypto_frames = connection.stats().frame_tx.crypto;
            if resumed {
                assert_eq!(crypto_frames, if hold { 1 } else { 2 });
            }
            let mut control = connection.open_uni().await.unwrap();
            control.write_all_and_finish(b"settings").await.unwrap();
            connection.closed().await;
            assert_eq!(connection.stats().frame_tx.crypto, 2);
        }
        assert_eq!(server_task.await.unwrap(), [b"settings"; 2]);
        client.wait_idle().await;
    }
}

/// A runtime that counts timers armed for deadlines that have already passed
#[derive(Debug, Default)]
struct DueTimerAudit(Arc<std::sync::atomic::AtomicUsize>);

impl DueTimerAudit {
    fn record(counter: &std::sync::atomic::AtomicUsize, deadline: Instant) {
        if deadline <= crate::Runtime::now(&TokioRuntime) {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl crate::Runtime for DueTimerAudit {
    fn new_timer(&self, t: Instant) -> std::pin::Pin<Box<dyn crate::AsyncTimer>> {
        Self::record(&self.0, t);
        Box::pin(AuditedTimer {
            inner: crate::Runtime::new_timer(&TokioRuntime, t),
            counter: self.0.clone(),
        })
    }

    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        crate::Runtime::spawn(&TokioRuntime, future)
    }

    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn crate::AsyncUdpSocket>> {
        crate::Runtime::wrap_udp_socket(&TokioRuntime, t)
    }

    fn now(&self) -> Instant {
        crate::Runtime::now(&TokioRuntime)
    }
}

#[derive(Debug)]
struct AuditedTimer {
    inner: std::pin::Pin<Box<dyn crate::AsyncTimer>>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::AsyncTimer for AuditedTimer {
    fn reset(mut self: std::pin::Pin<&mut Self>, i: Instant) {
        DueTimerAudit::record(&self.counter, i);
        self.inner.as_mut().reset(i)
    }

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

/// Deadlines that are already due are handled at once instead of through a runtime timer,
/// which would round them up to the runtime's next tick; after an asynchronous handshake, the
/// kept 1-RTT packets are processed right after the first 1-RTT data, with such a deadline
#[tokio::test]
async fn due_deadlines_skip_the_runtime_timer() {
    let _guard = subscribe();
    let factory = EndpointFactory::new();
    let server = factory.endpoint();
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut recv = connection.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(usize::MAX).await.unwrap(), b"settings");
        connection.closed().await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let client_crypto = rustls::ClientConfig::builder_with_provider(default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut fingerprint = crate::FingerprintConfig::default();
    fingerprint.buffered_packet_processing(crate::BufferedPacketProcessing::AfterFirst1rttData);
    let mut transport = TransportConfig::default();
    transport.fingerprint(fingerprint);
    let mut client_config = ClientConfig::new(Arc::new(ThreadedClientConfig {
        inner: Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()),
        delay: Duration::from_millis(5),
    }));
    client_config.transport_config(Arc::new(transport));
    let audit = DueTimerAudit::default();
    let due_timers = audit.0.clone();
    let client = Endpoint::new(
        EndpointConfig::default(),
        None,
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap(),
        Arc::new(audit),
    )
    .unwrap();
    let connection = client
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    send.write_all_and_finish(b"settings").await.unwrap();
    send.stopped().await.unwrap();
    connection.close(0u32.into(), b"done");
    server_task.await.unwrap();
    client.wait_idle().await;
    assert_eq!(due_timers.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// A transmit hold that is kept too long ends after 2 ms
#[tokio::test]
async fn transmit_hold_is_bounded() {
    let _guard = subscribe();
    let endpoint = endpoint();
    let server = endpoint.clone();
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut recv = connection.accept_uni().await.unwrap();
        recv.read_to_end(usize::MAX).await.unwrap()
    });
    let connection = endpoint
        .connect(endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let hold = connection.hold_transmit();
    let mut send = connection.open_uni().await.unwrap();
    let start = Instant::now();
    send.write_all_and_finish(b"held").await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("data held back for too long")
        .unwrap();
    assert_eq!(received, b"held");
    // Well below the timeout, allowing for a coarse runtime timer
    assert!(start.elapsed() < Duration::from_millis(100));
    drop(hold);
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
}
