// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The module is used to provide abstraction over TCP socket and UDS.

use std::fmt;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;

use futures::{Future, TryFutureExt};
use tokio::io::{AsyncRead, AsyncWrite};

// A unify version of `std::net::SocketAddr` and Unix domain socket.
#[derive(Debug)]
pub enum SocketAddr {
    Net(std::net::SocketAddr),
    // This could work on Windows in the future. See also rust-lang/rust#56533.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    UnixAbstract(Vec<u8>),
    // Windows named pipe, e.g. `\\.\pipe\sccache-<user>`.
    #[cfg(windows)]
    Pipe(String),
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::Net(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            SocketAddr::Unix(p) => write!(f, "{}", p.display()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            SocketAddr::UnixAbstract(p) => write!(f, "\\x00{}", p.escape_ascii()),
            #[cfg(windows)]
            SocketAddr::Pipe(p) => write!(f, "{}", p),
        }
    }
}

impl SocketAddr {
    /// Get a Net address that with IP part set to "127.0.0.1".
    #[inline]
    pub fn with_port(port: u16) -> Self {
        SocketAddr::Net(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    }

    #[inline]
    pub fn as_net(&self) -> Option<&std::net::SocketAddr> {
        match self {
            SocketAddr::Net(addr) => Some(addr),
            #[cfg(unix)]
            _ => None,
            #[cfg(windows)]
            SocketAddr::Pipe(_) => None,
        }
    }

    /// Parse a string as a unix domain socket.
    ///
    /// The string should follow the format of `self.to_string()`.
    #[cfg(unix)]
    pub fn parse_uds(s: &str) -> std::io::Result<Self> {
        // Parse abstract socket address first as it can contain any chars.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if s.starts_with("\\x00") {
                // Rust abstract path expects no prepend '\x00'.
                let data = crate::util::ascii_unescape_default(&s.as_bytes()[4..])?;
                return Ok(SocketAddr::UnixAbstract(data));
            }
        }
        let path = std::path::PathBuf::from(s);
        Ok(SocketAddr::Unix(path))
    }

    #[cfg(unix)]
    pub fn is_unix_path(&self) -> bool {
        matches!(self, SocketAddr::Unix(_))
    }

    #[cfg(not(unix))]
    pub fn is_unix_path(&self) -> bool {
        false
    }

    #[cfg(windows)]
    pub fn is_pipe(&self) -> bool {
        matches!(self, SocketAddr::Pipe(_))
    }

    #[cfg(not(windows))]
    pub fn is_pipe(&self) -> bool {
        false
    }

    /// Parse a string as a Windows named pipe address.
    ///
    /// A bare name (e.g. `sccache-foo`) is normalized to `\\.\pipe\sccache-foo`.
    /// An already-prefixed path (`\\.\pipe\...` or `\\<host>\pipe\...`) is passed
    /// through unchanged. The name component is sanitized so the result is always
    /// a valid pipe path: characters that are invalid in a pipe name (notably
    /// backslash, plus spaces and non-ASCII) are replaced with `_`.
    #[cfg(windows)]
    pub fn parse_pipe(s: &str) -> Self {
        const PREFIX: &str = r"\\.\pipe\";
        // Detect an already-prefixed path: `\\<server>\pipe\<name>`.
        let already_prefixed = {
            let lower = s.to_ascii_lowercase().replace('/', "\\");
            lower.starts_with(r"\\") && lower.contains(r"\pipe\")
        };
        if already_prefixed {
            return SocketAddr::Pipe(s.to_string());
        }
        // Sanitize the bare name: pipe names may not contain a backslash, and we
        // additionally fold spaces / non-ASCII to keep the path well-formed.
        let sanitized: String = s
            .chars()
            .map(|c| {
                if c == '\\' || c == '/' || c.is_whitespace() || !c.is_ascii_graphic() {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        SocketAddr::Pipe(format!("{PREFIX}{sanitized}"))
    }
}

// A helper trait to unify the behavior of TCP and UDS listener.
pub trait Acceptor {
    type Socket: AsyncRead + AsyncWrite + Unpin + Send;

    fn accept(&self) -> impl Future<Output = tokio::io::Result<Self::Socket>> + Send;
    fn local_addr(&self) -> tokio::io::Result<Option<SocketAddr>>;
}

impl Acceptor for tokio::net::TcpListener {
    type Socket = tokio::net::TcpStream;

    #[inline]
    fn accept(&self) -> impl Future<Output = tokio::io::Result<Self::Socket>> + Send {
        tokio::net::TcpListener::accept(self).and_then(|(s, _)| {
            // Failing here would end the accept loop: a connection the peer
            // already reset can refuse it.
            set_nodelay(&s, s.set_nodelay(true));
            futures::future::ok(s)
        })
    }

    #[inline]
    fn local_addr(&self) -> tokio::io::Result<Option<SocketAddr>> {
        tokio::net::TcpListener::local_addr(self).map(|a| Some(SocketAddr::Net(a)))
    }
}

// A helper trait to unify the behavior of TCP and UDS stream.
pub trait Connection: std::io::Read + std::io::Write + Send {
    fn try_clone(&self) -> std::io::Result<Box<dyn Connection>>;
}

impl Connection for std::net::TcpStream {
    #[inline]
    fn try_clone(&self) -> std::io::Result<Box<dyn Connection>> {
        let stream = std::net::TcpStream::try_clone(self)?;
        Ok(Box::new(stream))
    }
}

/// Report a failure to disable Nagle's algorithm on `stream`, which is not worth
/// failing the connection over. Without it, the last segment of a message
/// spanning several waits on the peer's delayed ACK.
fn set_nodelay(stream: &impl std::fmt::Debug, result: std::io::Result<()>) {
    if let Err(e) = result {
        warn!("failed to set TCP_NODELAY on {stream:?}: {e}");
    }
}

// Helper function to create a stream. Uses dynamic dispatch to make code more
// readable.
pub fn connect(addr: &SocketAddr) -> std::io::Result<Box<dyn Connection>> {
    match addr {
        SocketAddr::Net(addr) => {
            let stream = std::net::TcpStream::connect(addr)?;
            set_nodelay(&stream, stream.set_nodelay(true));
            Ok(Box::new(stream) as Box<dyn Connection>)
        }
        #[cfg(unix)]
        SocketAddr::Unix(p) => {
            std::os::unix::net::UnixStream::connect(p).map(|s| Box::new(s) as Box<dyn Connection>)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        SocketAddr::UnixAbstract(p) => {
            let sock = std::os::unix::net::SocketAddr::from_abstract_name(p)?;
            std::os::unix::net::UnixStream::connect_addr(&sock)
                .map(|s| Box::new(s) as Box<dyn Connection>)
        }
        #[cfg(windows)]
        SocketAddr::Pipe(p) => windows_imp::connect_pipe(p),
    }
}

#[cfg(unix)]
mod unix_imp {
    use futures::TryFutureExt;

    use super::*;

    impl Acceptor for tokio::net::UnixListener {
        type Socket = tokio::net::UnixStream;

        #[inline]
        fn accept(&self) -> impl Future<Output = tokio::io::Result<Self::Socket>> + Send {
            tokio::net::UnixListener::accept(self).and_then(|(s, _)| futures::future::ok(s))
        }

        #[inline]
        fn local_addr(&self) -> tokio::io::Result<Option<SocketAddr>> {
            let addr = tokio::net::UnixListener::local_addr(self)?;
            if let Some(p) = addr.as_pathname() {
                return Ok(Some(SocketAddr::Unix(p.to_path_buf())));
            }
            // TODO: support get addr from abstract socket.
            // tokio::net::SocketAddr needs to support `as_abstract_name`.
            // #[cfg(any(target_os = "linux", target_os = "android"))]
            // if let Some(p) = addr.0.as_abstract_name() {
            //     return Ok(SocketAddr::UnixAbstract(p.to_vec()));
            // }
            Ok(None)
        }
    }

    impl Connection for std::os::unix::net::UnixStream {
        #[inline]
        fn try_clone(&self) -> std::io::Result<Box<dyn Connection>> {
            let stream = std::os::unix::net::UnixStream::try_clone(self)?;
            Ok(Box::new(stream))
        }
    }
}

#[cfg(windows)]
pub mod windows_imp {
    use std::fs::OpenOptions;
    use std::io;
    use std::time::{Duration, Instant};

    use tokio::net::windows::named_pipe::{self, NamedPipeServer};

    use super::*;

    // `ERROR_PIPE_BUSY` (231): all instances of the pipe are busy. This maps to no
    // stable `io::ErrorKind`, so it must be matched on the raw OS error code.
    const ERROR_PIPE_BUSY: i32 = 231;

    /// How long to wait for a busy pipe.
    ///
    /// A server that is shutting down accepts no more clients, but its pipe stays
    /// busy rather than missing until its last request is done. Outwait that, so
    /// that the client can start a new server.
    const PIPE_BUSY_TIMEOUT: Duration =
        Duration::from_secs(crate::server::SHUTDOWN_TIMEOUT.as_secs() + 5);

    const _: () = assert!(PIPE_BUSY_TIMEOUT.as_secs() > crate::server::SHUTDOWN_TIMEOUT.as_secs());

    const PIPE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(20);

    impl Connection for std::fs::File {
        #[inline]
        fn try_clone(&self) -> io::Result<Box<dyn Connection>> {
            let f = std::fs::File::try_clone(self)?;
            Ok(Box::new(f))
        }
    }

    /// Connect to a named-pipe server by opening the pipe as a read+write file.
    ///
    /// A nonexistent pipe surfaces as `ErrorKind::NotFound` (the start-server
    /// trigger). `ERROR_PIPE_BUSY` is retried until [`PIPE_BUSY_TIMEOUT`].
    pub fn connect_pipe(path: &str) -> io::Result<Box<dyn Connection>> {
        connect_pipe_within(path, PIPE_BUSY_TIMEOUT)
    }

    pub(super) fn connect_pipe_within(
        path: &str,
        busy_timeout: Duration,
    ) -> io::Result<Box<dyn Connection>> {
        let start = Instant::now();
        loop {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(f) => return Ok(Box::new(f) as Box<dyn Connection>),
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && start.elapsed() < busy_timeout =>
                {
                    std::thread::sleep(PIPE_BUSY_RETRY_DELAY);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Create a single named-pipe server instance, mirroring the handshake pipe
    /// created in `commands.rs`. `first` must be true only for the first instance
    /// of a given name (it enables `first_pipe_instance`, which makes a second
    /// bind of the same name fail with `ERROR_ACCESS_DENIED`).
    pub fn create_pipe_server(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .access_inbound(true)
            .access_outbound(true)
            .in_buffer_size(65536)
            .out_buffer_size(65536)
            // TODO: restrict DACL to current user for a hardened security posture.
            .create(name)
    }

    /// An `Acceptor` over a Windows named pipe. Holds the next pre-created pipe
    /// instance; on `accept` it waits for a client to connect, arms a fresh
    /// instance for the next caller, and hands the connected instance back.
    pub struct NamedPipeAcceptor {
        name: String,
        pending: tokio::sync::Mutex<Option<NamedPipeServer>>,
    }

    impl NamedPipeAcceptor {
        pub fn bind(name: &str) -> io::Result<Self> {
            let first = create_pipe_server(name, true)?;
            Ok(NamedPipeAcceptor {
                name: name.to_string(),
                pending: tokio::sync::Mutex::new(Some(first)),
            })
        }
    }

    impl Acceptor for NamedPipeAcceptor {
        type Socket = NamedPipeServer;

        // The trait declares `+ Send` on the returned future; implementing this as
        // an `async fn` keeps that bound enforced (the held `MutexGuard` and
        // `NamedPipeServer` are both `Send`) while satisfying clippy::manual_async_fn.
        async fn accept(&self) -> io::Result<Self::Socket> {
            let mut g = self.pending.lock().await;
            let server = g.take().expect("pending instance present");
            server.connect().await?; // wait for a client
            *g = Some(create_pipe_server(&self.name, false)?); // arm the next
            Ok(server)
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(Some(SocketAddr::Pipe(self.name.clone())))
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::io;
    use std::io::{Read, Write};
    use std::time::Duration;

    use super::windows_imp::{
        NamedPipeAcceptor, connect_pipe, connect_pipe_within, create_pipe_server,
    };
    use super::*;

    fn unique_name(tag: &str) -> String {
        format!(r"\\.\pipe\sccache-test-{}-{}", std::process::id(), tag)
    }

    #[test]
    fn parse_pipe_normalizes_bare_name() {
        match SocketAddr::parse_pipe("sccache-foo") {
            SocketAddr::Pipe(p) => assert_eq!(p, r"\\.\pipe\sccache-foo"),
            other => panic!("expected Pipe, got {other:?}"),
        }
    }

    #[test]
    fn parse_pipe_passes_through_prefixed() {
        let full = r"\\.\pipe\sccache-bar";
        match SocketAddr::parse_pipe(full) {
            SocketAddr::Pipe(p) => assert_eq!(p, full),
            other => panic!("expected Pipe, got {other:?}"),
        }
    }

    #[test]
    fn parse_pipe_sanitizes_invalid_chars() {
        match SocketAddr::parse_pipe("with space\\and/slash") {
            SocketAddr::Pipe(p) => assert_eq!(p, r"\\.\pipe\with_space_and_slash"),
            other => panic!("expected Pipe, got {other:?}"),
        }
    }

    #[test]
    fn is_pipe_predicate() {
        assert!(SocketAddr::parse_pipe("sccache-foo").is_pipe());
        assert!(!SocketAddr::with_port(4226).is_pipe());
    }

    // A second `bind` of the same name surfaces the AddrInUse-equivalent: the
    // first-instance bind returns ERROR_ACCESS_DENIED (5) when the name is owned.
    #[test]
    fn double_bind_same_name_is_addr_in_use() {
        let name = unique_name("double-bind");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let _first = NamedPipeAcceptor::bind(&name).unwrap();
        let err = match NamedPipeAcceptor::bind(&name) {
            Ok(_) => panic!("second bind of the same name unexpectedly succeeded"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(5), "expected ERROR_ACCESS_DENIED");
    }

    // Connecting to a name with no server returns NotFound (the start-server trigger).
    #[test]
    fn connect_missing_pipe_is_not_found() {
        let name = unique_name("missing");
        let err = match connect_pipe(&name) {
            Ok(_) => panic!("connect to a nonexistent pipe unexpectedly succeeded"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // A server that is shutting down holds connected instances and offers none.
    // That is busy for as long as it lasts, and then missing, which makes the
    // client start a new server.
    #[test]
    fn busy_pipe_is_outwaited() {
        let name = unique_name("busy");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let draining = create_pipe_server(&name, true).unwrap();
        let _client = connect_pipe(&name).unwrap();

        let err = connect_pipe_within(&name, Duration::from_millis(100))
            .err()
            .expect("the only instance is taken");
        assert_eq!(err.raw_os_error(), Some(231), "expected ERROR_PIPE_BUSY");

        let waiter = {
            let name = name.clone();
            std::thread::spawn(move || connect_pipe(&name).err().map(|e| e.kind()))
        };
        std::thread::sleep(Duration::from_millis(500));
        assert!(!waiter.is_finished());
        drop(_client);
        drop(draining);
        assert_eq!(waiter.join().unwrap(), Some(io::ErrorKind::NotFound));
    }

    // Full round-trip: a client connects over the pipe, the acceptor hands the
    // server side to a task, and bytes flow in both directions.
    #[test]
    fn round_trip_over_pipe() {
        let name = unique_name("round-trip");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let acceptor = {
            let _g = rt.enter();
            NamedPipeAcceptor::bind(&name).unwrap()
        };

        // local_addr reports the pipe name we bound.
        match acceptor.local_addr().unwrap() {
            Some(SocketAddr::Pipe(p)) => assert_eq!(p, name),
            other => panic!("unexpected local_addr {other:?}"),
        }

        // Server task: accept one client, echo each byte doubled.
        let server = rt.spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut sock = acceptor.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            for b in &mut buf {
                *b = b.wrapping_mul(2);
            }
            sock.write_all(&buf).await.unwrap();
            sock.flush().await.unwrap();
        });

        // Client: blocking connect + exchange on this thread.
        let mut conn = connect_pipe(&name).unwrap();
        conn.write_all(&[1, 2, 3, 4]).unwrap();
        conn.flush().unwrap();
        let mut resp = [0u8; 4];
        conn.read_exact(&mut resp).unwrap();
        assert_eq!(resp, [2, 4, 6, 8]);

        rt.block_on(server).unwrap();
    }
}
