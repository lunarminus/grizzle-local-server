//! The container's health check: `grizzle-local healthcheck` exits 0 if the server answers.
//!
//! It asks wherever the server was told to listen (GRIZZLE_HOST / GRIZZLE_PORT), not a fixed
//! 127.0.0.1:9000, so changing either doesn't leave a healthy container marked unhealthy for ever.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::config::Settings;
use crate::net::upstream_host;

const TIMEOUT: Duration = Duration::from_secs(4);

/// The host and port to ask, given how the server is configured.
pub fn target(settings: &Settings) -> (String, u16) {
    (upstream_host(&settings.host), settings.port)
}

/// The URL the check asks, for messages.
pub fn url(settings: &Settings) -> String {
    let (host, port) = target(settings);
    if host.contains(':') {
        format!("http://[{host}]:{port}/health")
    } else {
        format!("http://{host}:{port}/health")
    }
}

/// GET /health from the server itself (directly: whatever http_proxy says, this is a request to
/// ourselves). `Ok` if it answers 200.
pub fn check(settings: &Settings) -> Result<(), String> {
    let (host, port) = target(settings);
    let address = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| format!("{host} is not an address"))?;
    let failed = |err: std::io::Error| err.to_string();
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT).map_err(failed)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(failed)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(failed)?;
    let request = format!("GET /health HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(failed)?;
    let mut head = [0u8; 64];
    let mut read = 0;
    while read < head.len() && !head[..read].contains(&b'\n') {
        match stream.read(&mut head[read..]).map_err(failed)? {
            0 => break,
            count => read += count,
        }
    }
    let status_line = String::from_utf8_lossy(&head[..read]);
    let status_line = status_line.lines().next().unwrap_or_default();
    match status_line.split(' ').nth(1) {
        Some("200") => Ok(()),
        _ => Err(format!("the server answered {status_line:?}")),
    }
}

/// Run the check with the settings of the environment; the process's exit code.
pub fn main() -> u8 {
    let outcome = Settings::from_env().and_then(|settings| check(&settings));
    match outcome {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("health check failed: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_asks_where_the_server_listens() {
        assert_eq!(url(&Settings::defaults()), "http://127.0.0.1:9000/health");
        let moved = Settings::from_pairs(&[("GRIZZLE_HOST", "192.168.1.5"), ("GRIZZLE_PORT", "9100")]).unwrap();
        assert_eq!(url(&moved), "http://192.168.1.5:9100/health");
        let six = Settings::from_pairs(&[("GRIZZLE_HOST", "::")]).unwrap();
        assert_eq!(url(&six), "http://[::1]:9000/health");
    }

    #[test]
    fn nothing_listening_is_unhealthy() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let settings = Settings::from_pairs(&[("GRIZZLE_HOST", "127.0.0.1"), ("GRIZZLE_PORT", &port.to_string())]).unwrap();
        assert!(check(&settings).is_err());
    }

    #[test]
    fn the_status_line_decides() {
        for (status, healthy) in [("200 OK", true), ("503 Service Unavailable", false), ("404 Not Found", false)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 512];
                let _ = stream.read(&mut request).unwrap();
                assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes()).unwrap();
            });
            let settings =
                Settings::from_pairs(&[("GRIZZLE_HOST", "127.0.0.1"), ("GRIZZLE_PORT", &port.to_string())]).unwrap();
            assert_eq!(check(&settings).is_ok(), healthy, "{status}");
            server.join().unwrap();
        }
    }
}
