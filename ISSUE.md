# DRAFT (not filed): TLS server: ALPN list passed to mbedTLS is dropped when `negotiate_server_init` returns

**Version:** esp-idf-svc 0.53.0 (and `master`, `src/tls.rs` identical), ESP-IDF v6.1, ESP32-S3.

`EspTls::negotiate_server_init` (`src/tls.rs:715`), which `EspAsyncTls::negotiate_server` (line
1026) uses, builds the ALPN protocol list in a stack local, `RawConfigBufs` (716), points
`esp_tls_cfg_server_t::alpn_protos` at it (`try_into_raw`, 467-470), calls
`esp_tls_server_session_init` (720) and drops the buffers (725-726) before returning.

esp-tls does not copy the list: `set_server_config` (`esp_tls_mbedtls.c:730-734`) calls
`mbedtls_ssl_conf_alpn_protocols`, which stores the pointer (`ssl_tls.c:2545`; the header requires
the table to live as long as the SSL configuration). mbedTLS reads it when the ClientHello's
ALPN extension arrives (`mbedtls_ssl_parse_alpn_ext`, `ssl_tls.c:8460`, `strlen(*alpn)`), and keeps
`ssl->alpn_chosen` pointing into the strings. With a non-blocking socket that is always after
`negotiate_server_init` has returned, so it reads a popped stack frame.

The blocking `negotiate_server` is not affected (it runs the whole handshake before dropping).

**Observed:** garbage ALPN list: the handshake fails with `-0x7580` (no application protocol) and
the client gets alert 120; in a larger app, LoadProhibited in `strlen` from `mbedtls_ssl_parse_alpn_ext`.

**Expected:** `h2` negotiated for `openssl s_client -alpn h2`.

**Reproducer:** <repo link>: a minimal app (Wi-Fi, TCP 443, `negotiate_server_init`/`_continue`
with `["h2", "http/1.1"]`), plus logs from an AtomS3 Lite. The `workaround` feature (a `'static`
list through `esp_tls_server_session_init`) negotiates `h2`.

**Suggested fix:** keep the array alive as long as the session: own a boxed `RawConfigBufs` in
`EspTls` (dropped with the session), or require `'static` protocol lists for the non-blocking path.
The client-side `Config::try_into_raw` (215-217) has the same shape and is worth checking.
