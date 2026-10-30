# Filed as esp-rs/esp-idf#626 (2026-10-30)

esp-idf-svc moved into the esp-rs/esp-idf monorepo; the old esp-rs/esp-idf-svc is archived.
Title: esp-idf-svc: TLS server's ALPN list dangles after negotiate_server_init returns (non-blocking/async handshake)

## Bug description

Line numbers below are esp-idf-svc 0.53.0's `src/tls.rs`. The same code is in this repo's
`esp-idf-svc/src/tls.rs` at 976-990 on `master` (64f82995).

`EspTls::negotiate_server_init` (`src/tls.rs:715`) is the non-blocking server handshake, and
`EspAsyncTls::negotiate_server` (line 1026) uses it. It builds the ALPN protocol list in a stack
local, `RawConfigBufs` (716), and points `esp_tls_cfg_server_t::alpn_protos` at it (`try_into_raw`,
467-470). Then it calls `esp_tls_server_session_init` (720) and drops the buffers (725-726) before
returning.

esp-tls doesn't copy the list:
- `set_server_config` (`components/esp-tls/esp_tls_mbedtls.c:730-734`) calls
  `mbedtls_ssl_conf_alpn_protocols`, which stores the pointer (`library/ssl_tls.c:2545`).
  `ssl.h` requires the table to live as long as the SSL configuration.
- mbedTLS reads the list when the ClientHello's ALPN extension arrives
  (`mbedtls_ssl_parse_alpn_ext`, `ssl_tls.c:8460-8461`, `strlen(*alpn)`).
- It keeps `ssl->alpn_chosen` pointing into the strings (8467).

With a non-blocking socket the ClientHello always arrives after `negotiate_server_init` has
returned, so mbedTLS reads a popped stack frame.

The blocking `negotiate_server` (682-704) isn't affected: `esp_tls_server_session_create` runs the
whole handshake before the buffers are dropped. The client side's `Config::try_into_raw`
(215-217) has the same shape. I haven't tested it, but it may be worth checking.

On an ESP32-S3 the list is already garbage by the first `negotiate_server_continue`. The handshake
fails with `mbedtls_ssl_handshake returned -0x7580` (`NO_APPLICATION_PROTOCOL`), and the client gets
alert 120, `no application protocol`. In a larger application (an HTTPS server on tokio), the same
bug showed as a `LoadProhibited` in `strlen` called from `mbedtls_ssl_parse_alpn_ext`.

- Would you like to work on a fix? n

## To Reproduce

Minimal reproducer: https://github.com/aeolionics-rs/esp-idf-svc-alpn. It brings up Wi-Fi, listens
on TCP 443, and runs `negotiate_server_init` / `negotiate_server_continue` with
`alpn_protos: Some(&["h2", "http/1.1"])`.

1. `cp cfg.toml.example cfg.toml` and fill in the Wi-Fi network.
2. `./flash.sh <port>` (builds and flashes; never erases), then
   `espflash monitor --non-interactive -p <port> --elf target/xtensa-esp32s3-espidf/release/esp-idf-svc-alpn`.
3. From the host: `echo | openssl s_client -alpn h2 -connect <device ip>:443`.

The device logs the list's words right after init (intact) and before the first `continue`
(overwritten), then the handshake fails:

```
I (15575) esp_idf_svc_alpn: ALPN list after init: alpn_list=0x3fca6784 words=0x3fca67ac 0x3fca67af 0x0 (caller's stack near 0x3fca687b); want two pointers to "h2" and "http/1.1", then null
I (15575) esp_idf_svc_alpn: ALPN list before first continue: alpn_list=0x3fca6784 words=0x3fc96c88 0x3cd7 0x3fca6778 (caller's stack near 0x3fca687b); want two pointers to "h2" and "http/1.1", then null
E (15585) esp_idf_svc_alpn: handshake failed: ESP_FAIL
```

```
SSL routines:ssl3_read_bytes:tlsv1 alert no application protocol ... SSL alert number 120
No ALPN negotiated
```

Variants:
- `./flash.sh <port> scribble` overwrites the stack below the caller between init and continue,
  and gives the same failure with the words `0xa5a5a5a5`.
- `./flash.sh <port> workaround` passes a `'static` list straight to `esp_tls_server_session_init`.
  It negotiates `h2` (`ALPN protocol: h2`).

Logs of all three runs are in the repo's `logs/`.

`init` has to stay out of line (`#[inline(never)]` in the reproducer). When it was inlined into its
caller, the array happened to stay in a live frame and `h2` negotiated, which hides the bug.

Reproduced with 0.53.0. This repo's `master` (64f82995) still has the same
`negotiate_server_init`, but I haven't run it.

## Expected behavior

`h2` is negotiated for `openssl s_client -alpn h2`. The non-blocking server handshake then behaves
like the blocking one.

Suggested fix: keep the array alive as long as the session. Either own a boxed `RawConfigBufs` in
`EspTls`, dropped with the session, or require `'static` protocol lists on the non-blocking path.

## Environment

- Crate (`esp-idf-sys`, `esp-idf-hal` or `esp-idf-svc`) and version: esp-idf-svc 0.53.0 (the code is unchanged on `master`, 64f82995)
- ESP-IDF branch or tag: v6.1
- Target device (MCU): esp32s3 (M5Stack AtomS3 Lite)
- OS: Ubuntu 26.04.1 LTS

Found by Jeremy Boynes with Claude (Anthropic) doing the analysis and the reproducer.
