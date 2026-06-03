# Plan: Windows Named-Pipe Transport for sccache

## Context

On Windows, the sccache client and server communicate over a TCP localhost socket
(default port 4226). When the server process is hard-killed (`TerminateProcess`,
Task Manager "End Task", or a crash), the listening socket can be left orphaned —
the port stays in `LISTENING` state owned by a now-dead PID, because the listening
socket handle was inherited by a child/grandchild process (sccache spawns the
server and compiler subprocesses with inherited handles via `CreateProcessW`). A
new server then cannot bind the port, and the only fixes are a reboot or
`netsh int ip reset`. This was hit in practice (PID 36520 holding 4226 with no live
process).

Named pipes eliminate this failure class: there is no TCP port to orphan, pipe
instances are kernel objects reference-counted and destroyed when the last handle
closes, and a fresh server simply creates a new instance under the same name.

This is an **opt-in** transport (activated by `SCCACHE_SERVER_PIPE`), parallel to
the existing unix `SCCACHE_SERVER_UDS`. TCP remains the Windows default, so the
change is non-breaking. Security posture for v1 is Windows' default pipe DACL plus
`reject_remote_clients(true)` — the same trust model as the current TCP localhost
socket, with no new `unsafe` code.

## Why this fits the existing design

The server is already generic over the transport: `SccacheServer<A: net::Acceptor>`
(`src/server.rs:571`) and its accept loop only do `listener.accept().await` →
`service.bind(socket)` where `socket: AsyncRead + AsyncWrite + Send`. The client
side uses a **synchronous** `Connection: Read + Write` trait (`src/net.rs:115`).
Both halves already exist for Windows pipes:
- `tokio::net::windows::named_pipe::NamedPipeServer` implements
  `AsyncRead+AsyncWrite+Unpin+Send` → satisfies `Acceptor::Socket`. It is already
  used for the startup handshake in `commands.rs:263-291`.
- A pipe client is a plain `std::fs::File` opened read+write — exactly what
  `notify_server_startup` already does (`server.rs:128`). `File` is `Read+Write` and
  has `try_clone`, so `impl Connection for File` is trivial.

No changes to the request/response service layer, codec, or `client.rs` are needed.

## Implementation

### Step 1 — `src/net.rs` (foundation)

Add a `#[cfg(windows)]` variant and its dispatch, mirroring the `Unix` scaffolding:

- `enum SocketAddr`: add `#[cfg(windows)] Pipe(String)` (full path,
  `\\.\pipe\sccache-<user>`).
- `impl Display`: add `Pipe(p) => write!(f, "{p}")`. **Must format identically to
  what the server reports** (see equality check in Step 2).
- `as_net()`: add a `#[cfg(windows)] SocketAddr::Pipe(_) => None` arm so the match
  stays exhaustive on Windows (currently `Net` is the only Windows variant).
- Predicates: `#[cfg(windows)] pub fn is_pipe(&self) -> bool` (matches `Pipe`);
  `#[cfg(not(windows))] pub fn is_pipe(&self) -> bool { false }`.
- `parse_pipe(s: &str) -> SocketAddr` (`#[cfg(windows)]`): normalize a bare name to
  `\\.\pipe\<name>`, pass through an already-prefixed path. Sanitize the
  `<username>` (spaces / non-ASCII → fall back to a hash or SID) so the name is
  always a valid pipe path.
- `connect()`: add `#[cfg(windows)] SocketAddr::Pipe(p) => connect_pipe(p)`.
- New `#[cfg(windows)] mod windows_imp` containing:
  - `impl Connection for std::fs::File { try_clone }`.
  - `fn connect_pipe(path) -> io::Result<Box<dyn Connection>>`:
    `OpenOptions::new().read(true).write(true).open(path)`, with a short bounded
    retry on `ERROR_PIPE_BUSY` (matched via `e.raw_os_error() == Some(ERROR_PIPE_BUSY)`,
    **not** an `ErrorKind`). Nonexistent pipe returns `ErrorKind::NotFound`.
  - `fn create_pipe_server(name, first) -> io::Result<NamedPipeServer>` mirroring the
    existing `create_named_pipe` (`commands.rs:263`): `first_pipe_instance(first)`,
    `reject_remote_clients(true)`, `access_inbound/outbound(true)`, 64KiB buffers,
    default `max_instances` (unlimited). This is the seam where a hardened DACL would
    later go (leave a `// TODO: restrict DACL to current user` marker).
  - `struct NamedPipeAcceptor { name: String, pending: tokio::sync::Mutex<Option<NamedPipeServer>> }`
    with `fn bind(name) -> io::Result<Self>` (creates the first instance) and
    `impl Acceptor`:
    ```rust
    fn accept(&self) -> impl Future<Output = io::Result<NamedPipeServer>> + Send {
        async move {
            let mut g = self.pending.lock().await;
            let server = g.take().expect("pending instance present");
            server.connect().await?;                       // wait for a client
            *g = Some(create_pipe_server(&self.name, false)?); // arm the next
            Ok(server)
        }
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(SocketAddr::Pipe(self.name.clone())))
    }
    ```
    This refactors the existing `try_unfold` connect/recreate idiom into an
    `Acceptor`. The `tokio::sync::Mutex` only satisfies `&self` (the accept loop is
    single-task). **Verify the returned future is `Send`** — `MutexGuard` and
    `NamedPipeServer` are `Send`, so it should hold. Fallback if not: use a
    `std::sync::Mutex` guarding only the synchronous take/replace and await
    `.connect()` outside the lock.

### Step 2 — `src/commands.rs` (address selection + start path)

- `get_addr()` (`commands.rs:52`): before the TCP fallback, add
  ```rust
  #[cfg(windows)]
  if let Ok(name) = env::var("SCCACHE_SERVER_PIPE") {
      return crate::net::SocketAddr::parse_pipe(&name);
  }
  ```
  (Placed after the unix `SCCACHE_SERVER_UDS` block; both are cfg-gated so only one
  compiles per platform.)
- `connect_or_start_server` (`commands.rs:313`): generalize the start-trigger guard:
  ```rust
  || (e.kind() == io::ErrorKind::NotFound && (addr.is_unix_path() || addr.is_pipe()))
  ```
  (`NotFound` = pipe/UDS missing → start server; `ConnectionRefused`/`TimedOut`
  still cover TCP. No overlap.)
- **No change to the handshake** in `run_server_process`: it keeps its own random-UUID
  notify pipe, and the spawned child inherits all `SCCACHE_*` env vars
  (`commands.rs:212` copies `env::vars_os()`), so the child's `get_addr()` picks up
  `SCCACHE_SERVER_PIPE` automatically.

### Step 3 — `src/server.rs` (bind arm)

- `start_server` match (`server.rs:493`): add
  ```rust
  #[cfg(windows)]
  crate::net::SocketAddr::Pipe(name) => {
      trace!("binding named pipe {name}");
      let l = { let _g = runtime.enter(); net::windows_imp::NamedPipeAcceptor::bind(name)? };
      let srv = SccacheServer::<_>::with_listener(l, runtime, client, dist_client, storage);
      Ok((srv.local_addr().unwrap(),
          Box::new(move |f| srv.run(f)) as Box<dyn FnOnce(_) -> _>))
  }
  ```
  Bind inside `runtime.enter()` (tokio resource registration), same as the
  abstract-UDS arm. `with_listener`/`run` are already generic over `A: Acceptor`.
- Error mapping (`server.rs:540-561`): in the `Err(e)` arm, if `addr.is_pipe()` and
  the OS error means the name is already owned (`ERROR_ACCESS_DENIED` /
  `ERROR_PIPE_BUSY` on the first instance), send `ServerStartup::AddrInUse` so
  parallel bootstraps retry cleanly (the existing `AddrInUse`/WSAEACCES handling is
  TCP-specific).
- `SccacheServer::new` (`server.rs:580`, `as_net().unwrap()`): no change — it is
  TCP-only and used only by tests, which never construct `Pipe`. The new `as_net`
  arm returning `None` does not affect it.

### Step 4 — `src/client.rs`

No changes. `connect_to_server`/`connect_with_retry` already route through
`net::connect` and the synchronous `Connection`/`ServerConnection`; the `File`-based
pipe connection slots in transparently. `connect_with_retry` (10×/500ms) plus the
in-`connect_pipe` busy-retry cover transient `ERROR_PIPE_BUSY`.

### Step 5 — Tests & docs

- Add a `#[cfg(windows)]` integration test: set `SCCACHE_SERVER_PIPE`, start a
  server, round-trip a `GetStats` (or compile) request, shut down. Existing TCP
  tests (`test/tests.rs`, which assert `Net`) are left unchanged.
- Add a test that a second `NamedPipeAcceptor::bind` of the same name surfaces the
  `AddrInUse`-equivalent.
- Document `SCCACHE_SERVER_PIPE` alongside `SCCACHE_SERVER_PORT` /
  `SCCACHE_SERVER_UDS` (README + `docs/`), with the rationale (TerminateProcess
  orphaning the TCP listener) and the v1 security posture (default DACL +
  `reject_remote_clients`).

## Sequencing

Step 1 is the foundation. Steps 2 and 3 are independent and can follow in either
order. Step 4 is verify-only. Step 5 last. Every new arm is `#[cfg(windows)]`-gated,
so the tree compiles incrementally and non-Windows builds are untouched.

## Files

- `src/net.rs` — variant, dispatch, `NamedPipeAcceptor`, `connect_pipe`, `Connection for File` (primary work)
- `src/commands.rs` — `get_addr`, `connect_or_start_server` guard
- `src/server.rs` — `start_server` bind arm + pipe `AddrInUse` mapping
- `src/client.rs` — verify only, no edits expected
- README / `docs/` — document `SCCACHE_SERVER_PIPE`
- `Cargo.toml` — no change for v1 (`Win32_Security` already enabled; hardened DACL
  would be a follow-up needing extra `windows-sys` features)

## Verification

1. **Build (non-Windows unaffected):** `cargo build` on Windows;
   `cargo clippy` and `cargo build` cross-check that cfg-gating is correct.
2. **Functional round-trip:**
   ```powershell
   $env:SCCACHE_SERVER_PIPE = "sccache-test"
   cargo run -- --stop-server        # ensure clean
   cargo run -- --start-server
   cargo run -- --show-stats         # should connect over the pipe
   ```
   Confirm `netstat -ano | findstr :4226` shows **nothing** (no TCP port opened).
3. **Leak repro is gone:** start the server over the pipe, then hard-kill it
   (`Stop-Process -Id <pid> -Force`). A subsequent `--start-server` must succeed
   immediately (fresh pipe instance), with no orphaned-port / `AddrInUse` error.
4. **Concurrency:** run several `--show-stats` in parallel against one server;
   all succeed (unlimited pipe instances).
5. **Tests:** `cargo test` (the new Windows-gated pipe test + existing suite).
