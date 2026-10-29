//! Reproducer: esp-idf-svc 0.53.0's `EspTls::negotiate_server_init` (and so
//! `EspAsyncTls::negotiate_server`) hands mbedTLS an ALPN list that is dead once it returns.
//!
//! Brings Wi-Fi up, accepts one TCP connection at a time on port 443 and runs a server handshake
//! offering ALPN ["h2", "http/1.1"]. Drive it with `openssl s_client -alpn h2 -connect <ip>:443`.
//! It logs the protocol it negotiated, or crashes (LoadProhibited in strlen, called from
//! mbedtls_ssl_parse_alpn_ext) while parsing the ClientHello.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::os::fd::{AsRawFd as _, IntoRawFd as _};
use std::time::Duration;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::{
    ESP_TLS_ERR_SSL_WANT_READ, ESP_TLS_ERR_SSL_WANT_WRITE, EspError, esp_tls_get_ssl_context,
    mbedtls_ssl_get_alpn_protocol,
};
use esp_idf_svc::tls::{EspTls, Socket};
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASS");
// Self-signed, generated for this repro; NUL-terminated for mbedTLS's PEM parser.
const CERT: &str = concat!(include_str!("../certs/cert.pem"), "\0");
const KEY: &str = concat!(include_str!("../certs/key.pem"), "\0");
const ALPN: [&str; 2] = ["h2", "http/1.1"];

/// The socket as esp-tls sees it: its descriptor, which esp-tls closes with the session.
struct Fd(i32);

impl Socket for Fd {
    fn handle(&self) -> i32 {
        self.0
    }

    fn release(&mut self) -> Result<(), EspError> {
        Ok(())
    }
}

/// Starts the server handshake on the adopted socket, with the library's call.
#[cfg(not(feature = "workaround"))]
#[inline(never)] // as in any caller where the library call returns before the handshake continues: the frame holding its array is popped
fn init(tls: &mut EspTls<Fd>, _fd: i32) -> Result<(), EspError> {
    use esp_idf_svc::tls::{ServerConfig, X509};
    let mut cfg = ServerConfig::new();
    cfg.alpn_protos = Some(&ALPN);
    cfg.server_cert = Some(X509::pem_until_nul(CERT.as_bytes()));
    cfg.server_key = Some(X509::pem_until_nul(KEY.as_bytes()));
    // Builds the C array of ALPN names in a local and drops it before returning.
    tls.negotiate_server_init(&cfg)
}

/// The same, calling esp-tls directly with a 'static ALPN list.
#[cfg(feature = "workaround")]
fn init(tls: &mut EspTls<Fd>, fd: i32) -> Result<(), EspError> {
    use esp_idf_svc::sys::{esp, esp_tls_cfg_server, esp_tls_server_session_init};
    struct Protocols([*const core::ffi::c_char; 3]);
    // SAFETY: pointers to static strings, never written.
    unsafe impl Sync for Protocols {}
    static PROTOCOLS: Protocols = Protocols([c"h2".as_ptr(), c"http/1.1".as_ptr(), core::ptr::null()]);
    assert_eq!(ALPN, ["h2", "http/1.1"]);

    let mut cfg = esp_tls_cfg_server { alpn_protos: PROTOCOLS.0.as_ptr().cast_mut(), ..Default::default() };
    cfg.__bindgen_anon_3.servercert_buf = CERT.as_ptr();
    cfg.__bindgen_anon_4.servercert_bytes = CERT.len() as u32;
    cfg.__bindgen_anon_5.serverkey_buf = KEY.as_ptr();
    cfg.__bindgen_anon_6.serverkey_bytes = KEY.len() as u32;
    // SAFETY: the certificate, key and ALPN list are static.
    esp!(unsafe { esp_tls_server_session_init(&raw mut cfg, fd, tls.context_handle()) })
}

/// Stands in for whatever a caller does after `negotiate_server_init` (logging, awaiting, polling):
/// it uses the stack below the caller, where the library's array was.
#[cfg(feature = "scribble")]
#[inline(never)]
fn scribble() {
    let mut junk = [0xA5u8; 6144];
    std::hint::black_box(&mut junk);
}

/// Logs where mbedTLS's ALPN list is (`conf->alpn_list`), where this stack is, and what the list
/// holds now. Reads memory the library may have let go of: a diagnostic, not part of the repro.
fn show_alpn(tls: &EspTls<Fd>, when: &str) {
    let marker = 0u8;
    // SAFETY: the session's mbedTLS context; the reads of the list itself are the point.
    unsafe {
        let ssl = esp_tls_get_ssl_context(tls.context_handle());
        let ssl = ssl.cast::<esp_idf_svc::sys::mbedtls_ssl_context>();
        let list = (*(*ssl).conf).alpn_list;
        // The three words of the list, as the pointers they should be (names, then null); the
        // names are not dereferenced, as what they point at may be gone.
        let w = |i| *list.add(i);
        log::info!(
            "ALPN list {when}: alpn_list={list:p} words={:p} {:p} {:p} (caller's stack near {:p}); want two pointers to \"h2\" and \"http/1.1\", then null",
            w(0), w(1), w(2), &raw const marker
        );
    }
}

fn serve_one(stream: std::net::TcpStream) -> anyhow::Result<()> {
    stream.set_nonblocking(true)?;
    let fd = stream.as_raw_fd();
    let mut tls = EspTls::adopt(Fd(fd))?;
    init(&mut tls, fd)?;
    show_alpn(&tls, "after init");
    #[cfg(feature = "scribble")]
    scribble();
    show_alpn(&tls, "before first continue");
    // From here on mbedTLS reads the ALPN list: when the ClientHello arrives.
    let started = std::time::Instant::now();
    loop {
        match tls.negotiate_server_continue() {
            Ok(()) => break,
            Err(e) if e.code() == ESP_TLS_ERR_SSL_WANT_READ || e.code() == ESP_TLS_ERR_SSL_WANT_WRITE => {
                if started.elapsed() > Duration::from_secs(10) {
                    anyhow::bail!("handshake timed out");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                // The fd now belongs to the session; esp-tls closes it when the session drops.
                let _ = stream.into_raw_fd();
                anyhow::bail!("handshake failed: {e}");
            }
        }
    }
    // SAFETY: the session's mbedTLS context, alive while `tls` is.
    let alpn = unsafe {
        let ssl = esp_tls_get_ssl_context(tls.context_handle());
        let p = mbedtls_ssl_get_alpn_protocol(ssl.cast());
        (!p.is_null()).then(|| std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned())
    };
    show_alpn(&tls, "after handshake");
    log::info!("RESULT: negotiated ALPN = {alpn:?} (expected Some(\"h2\"))");
    let _ = stream.into_raw_fd();
    Ok(())
}

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;
    let mut wifi = BlockingWifi::wrap(EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs))?, sysloop)?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        password: PASSWORD.try_into().unwrap(),
        auth_method: if PASSWORD.is_empty() { AuthMethod::None } else { AuthMethod::WPA2Personal },
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.connect()?;
    wifi.wait_netif_up()?;
    let ip = wifi.wifi().sta_netif().get_ip_info()?.ip;
    log::info!("up: run  openssl s_client -alpn h2 -connect {ip}:443  (workaround: {})", cfg!(feature = "workaround"));

    let listener = TcpListener::bind("0.0.0.0:443")?;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                log::info!("connection from {peer}");
                if let Err(e) = serve_one(stream) {
                    log::error!("{e:#}");
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}
