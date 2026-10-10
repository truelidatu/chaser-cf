use chaser_cf::{ChaserCF, ChaserConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// Run explicitly on a machine with Chrome installed:
// cargo test --test waf_navigation -- --ignored
#[tokio::test]
#[ignore = "requires Chrome"]
async fn direct_page_and_challenge_redirect_succeed_without_cookies() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("chaser_cf=debug,chaser_oxide=warn")
        .try_init();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let count = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                let (status, extra_headers, body) = if request.starts_with("GET /challenge ") {
                    (
                        "403 Forbidden",
                        "cf-mitigated: challenge\r\n",
                        "<script>location.replace('/destination')</script>",
                    )
                } else {
                    ("200 OK", "", "<html><body>Destination</body></html>")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });

    let config = ChaserConfig::default()
        .with_headless(true)
        .with_timeout_ms(10_000);
    let chaser = ChaserCF::new(config).await.unwrap();

    let direct = chaser
        .solve_waf_session(&format!("http://{address}/direct"), None)
        .await
        .unwrap();
    assert!(direct.cookies.is_empty());

    let challenged = chaser
        .solve_waf_session(&format!("http://{address}/challenge"), None)
        .await
        .unwrap();
    assert!(challenged.cookies.is_empty());

    chaser.shutdown().await;
    server.abort();
}
