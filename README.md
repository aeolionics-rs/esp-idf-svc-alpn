# esp-idf-svc 0.53.0: ALPN list dangles after `negotiate_server_init`

A use-after-return in esp-idf-svc 0.53.0's TLS server code. `EspTls::negotiate_server_init`, and so
`EspAsyncTls::negotiate_server`, builds the ALPN protocol list in a local, hands mbedTLS a pointer
to it, and returns. The local is gone; mbedTLS reads it later, when the ClientHello arrives.

Result: the handshake is rejected with `no_application_protocol` (garbage list), or a
LoadProhibited exception in `strlen` called from `mbedtls_ssl_parse_alpn_ext` (seen in a larger
async app on an AtomS3R). With a static list the same code negotiates `h2`.

## Versions

| | |
|---|---|
| esp-idf-svc | 0.53.0 (latest release on crates.io, 2026-09-15; `master` (c8bcc9d7, 2026-09-19): src/tls.rs is byte-identical to 0.53.0) |
| esp-idf-sys | 0.38.1 |
| ESP-IDF | v6.1 (checkout fff9895c), mbedTLS 4.1.0 |
| Rust | `esp` toolchain, rustc 1.97.0-nightly (8ea53bcd7 2026-07-08) |
| Board | M5Stack AtomS3 Lite (ESP32-S3FN8) |

## The code path

esp-idf-svc 0.53.0, `src/tls.rs`:

- `negotiate_server_init`, lines 715-729: `let mut bufs = RawConfigBufs::default();` (716) puts the
  array on the stack. `cfg.try_into_raw(&mut bufs)` (717) fills it and points the config at it.
  `esp_tls_server_session_init(&mut rcfg, ...)` (720-722) hands the config over. `drop(bufs)`
  (725-726) ends the array's life; the function returns at 728. The comment at the equivalent
  blocking function (line 696, "Make sure buffers are held long enough"; the same comment is at 591, 659 and 1006) shows the intent, but
  only the blocking `negotiate_server` (682-704) is safe: `esp_tls_server_session_create` runs the
  whole handshake before it returns.
- `try_into_raw`, lines 467-470: `bufs.alpn_protos = cstr_arr_from_str_slice(protos, &mut bufs.alpn_protos_cbuf)?;
  rcfg.alpn_protos = bufs.alpn_protos.as_mut_ptr();` The pointer array (`[*const c_char; 10]`) and
  the bytes it points at (`[u8; 99]`) are both in `RawConfigBufs` (lines 286-289), a stack local of the caller.
  `cstr_arr_from_str_slice` is in `src/private/cstr.rs:142`.
- `EspAsyncTls::negotiate_server`, lines 1026-1037: calls `negotiate_server_init` (1027), then loops on
  `negotiate_server_continue` (1030) across `.await`s. The stack frame is long gone by then, and
  the future may run on another stack depth.

ESP-IDF v6.1, `components/esp-tls/esp_tls_mbedtls.c`:

- `esp_mbedtls_server_session_init` (1236) installs `set_server_config` (1244: `server_params.set_server_cfg = &set_server_config;`).
- `set_server_config` (712), lines 730-734:
  ```c
  #ifdef CONFIG_MBEDTLS_SSL_ALPN
      if (cfg->alpn_protos) {
          mbedtls_ssl_conf_alpn_protocols(&tls->conf, cfg->alpn_protos);
      }
  ```
  The pointer, not a copy. esp-tls keeps no copy of `cfg` either (`esp_tls_cfg_server_t` lives in the caller).

mbedTLS 4.1.0 (`components/mbedtls/mbedtls/library/ssl_tls.c`):

- `mbedtls_ssl_conf_alpn_protocols`, lines 2522-2548: validates the lengths, then
  `conf->alpn_list = protos;` (2545). Pointer kept.
- `mbedtls_ssl_parse_alpn_ext`, line 8407 on: `ssl->conf->alpn_list` is walked when the ClientHello's
  ALPN extension is parsed (8460: `for (const char *const *alpn = ssl->conf->alpn_list; *alpn != NULL; alpn++) { size_t const alpn_len = strlen(*alpn);`)
  and `ssl->alpn_chosen = *alpn;` (8467) keeps a pointer *into the string too*, which
  `mbedtls_ssl_get_alpn_protocol` (2552) returns later. So the list and the names must outlive the session.
- `include/mbedtls/ssl.h:4128`: "the lifetime of the table must be at least as long as the lifetime of the SSL configuration structure."

The ClientHello arrives after `negotiate_server_init` has returned (a non-blocking socket has
nothing to read yet), so the read is always after the array's death.

(The client side has the same shape: `Config::try_into_raw` at line 215-217 does the same for
`alpn_protos`. Not tried here.)

## Reproduce

Hardware: any ESP32-S3 on Wi-Fi (built for the AtomS3 Lite, 8 MB flash).

```sh
cp cfg.toml.example cfg.toml        # fill in [wifi]; git ignores it
# espup's `esp` toolchain (rust-toolchain.toml), ldproxy and espflash installed
./flash.sh /dev/ttyACM0                 # the library call (build + flash, no erase)
espflash monitor -p /dev/ttyACM0 --elf target/xtensa-esp32s3-espidf/release/esp-idf-svc-alpn
# the log says: up: run  openssl s_client -alpn h2 -connect <ip>:443
echo | openssl s_client -alpn h2 -connect <ip>:443
```

Variants: `./flash.sh PORT scribble` (overwrites the stack below the caller between init and
the first continue, which any real caller's later calls do; makes the failure certain),
`./flash.sh PORT workaround` (esp_tls_server_session_init with a `'static` list).
`logs/drive.sh PORT NAME` monitors and runs openssl in one go (what produced `logs/`).
`flash.sh` flashes the partition table in `partitions.csv`, never erases.

### Results (AtomS3 Lite, 2026-10-29; `logs/`)

| build | device | openssl |
|---|---|---|
| library | `ALPN list after init`: `alpn_list` points into the caller's stack, words intact. `before first continue` (after a log line): words are `0x3fc96c88 0x3cd7 0x3fca6778`, no longer the two string pointers and a null. `mbedtls_ssl_handshake returned -0x7580` (NO_APPLICATION_PROTOCOL) | `alert no application protocol`, "No ALPN negotiated" |
| library + scribble | words `0xa5a5a5a5 ...`; same -0x7580 | same |
| workaround | `alpn_list=0x3c0e2988` (static data), words intact all through; `negotiated ALPN = Some("h2")` | `ALPN protocol: h2` |

Not reproduced here: the LoadProhibited in `strlen`. It needs the dead stack slot to hold a
non-null, invalid pointer in `alpn_list[0]` at the moment the ClientHello is parsed. In this small
app the handshake's own frames rewrite the slot first (to null, so no protocol matches and the
server sends the `no_application_protocol` alert). In the larger async app (tokio, hyper, other
handshakes in flight) it crashed. The logs show the list's words changing after
`negotiate_server_init` returned, which is the bug; whether it ends as garbage ALPN, a rejected
handshake or a crash depends on what the stack holds.

Note on inlining: `init` is `#[inline(never)]`. If the compiler inlines `negotiate_server_init`
into a caller that stays on the stack (as it did when `init` was inlined into `serve_one`), the array
sits in the caller's frame, is not reused, and the handshake happens to negotiate `h2`. The bug is
then hidden, not absent.

## Without hardware

The code walk-through above is the host-side evidence: the array is a local in a function that has
returned (esp-idf-svc `src/tls.rs:716-728`), and mbedTLS keeps the pointer (`ssl_tls.c:2545`) and
dereferences it later (`ssl_tls.c:8460`). Rust cannot catch it because the pointer goes through a C
struct (`rcfg.alpn_protos`, a raw pointer), and `drop(bufs)` with the lint allowed
(`#[allow(clippy::drop_non_drop)]`) only reads as keeping it alive.

## Workaround

Call `esp_tls_server_session_init` yourself with a `'static` list (see `init` under
`#[cfg(feature = "workaround")]` in `src/main.rs`):

```rust
struct Protocols([*const c_char; 3]);
unsafe impl Sync for Protocols {}
static PROTOCOLS: Protocols = Protocols([c"h2".as_ptr(), c"http/1.1".as_ptr(), core::ptr::null()]);
let mut cfg = esp_tls_cfg_server { alpn_protos: PROTOCOLS.0.as_ptr().cast_mut(), ..Default::default() };
```

## Suggested fix

Keep the array alive as long as the TLS session (as long as `ssl->conf`):

- own `RawConfigBufs` (or just the ALPN part) in the `EspTls` and drop it with the session (a
  `Box<RawConfigBufs>`, so its address is stable), filled by `negotiate_server_init`; or
- take the protocols as `&'static [&'static CStr]` / a `'static` array in `ServerConfig`
  for the non-blocking path; or
- copy the protocols into a heap allocation owned by the session.

The same holds for every pointer in `esp_tls_cfg_server` that mbedTLS keeps after init (the
certificates are parsed during `server_session_init`, so those are fine, as the doc says; the ALPN
list, and `serverkey_password` only during init, are the ones to check).
