use std::{
    collections::HashSet,
    fmt,
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use hickory_resolver::TokioResolver;
use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{Mutex, mpsc},
    time::{sleep, timeout},
};

const SMTP_PORT: u16 = 25;
const CIRCUIT_BREAKER_FAILURES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Accepted,
    Rejected,
    Unknown,
    Invalid,
}

impl fmt::Display for ProbeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => write!(formatter, "accepted"),
            Self::Rejected => write!(formatter, "rejected"),
            Self::Unknown => write!(formatter, "unknown"),
            Self::Invalid => write!(formatter, "invalid"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub email: String,
    pub status: ProbeStatus,
    pub code: Option<u16>,
    pub mx: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
struct MxEndpoint {
    host: String,
    addresses: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct PreflightInfo {
    pub mx: String,
    pub address: SocketAddr,
    pub pipelining: bool,
}

#[derive(Clone)]
pub struct SmtpProber {
    endpoints: Arc<Vec<MxEndpoint>>,
    from: String,
    helo: String,
    connect_timeout: Duration,
    command_timeout: Duration,
    disable_pipelining: bool,
    consecutive_failures: Arc<AtomicUsize>,
    preferred_address: Arc<RwLock<Option<(String, SocketAddr)>>>,
}

impl SmtpProber {
    pub async fn discover(
        domain: &str,
        from: Option<String>,
        connect_timeout: Duration,
        command_timeout: Duration,
        disable_pipelining: bool,
    ) -> Result<Self> {
        if let Some(value) = from.as_deref() {
            validate_envelope_sender(value)?;
        }
        let resolver = TokioResolver::builder_tokio()
            .context("could not initialize the DNS resolver")?
            .build();
        let lookup = resolver
            .mx_lookup(domain)
            .await
            .with_context(|| format!("could not resolve MX records for {domain}"))?;
        let mut records: Vec<_> = lookup.iter().collect();
        records.sort_by_key(|record| record.preference());

        let mut endpoints = Vec::new();
        let mut seen_hosts = HashSet::new();
        for record in records {
            let host = record.exchange().to_utf8().trim_end_matches('.').to_owned();
            if host.is_empty() || !seen_hosts.insert(host.clone()) {
                continue;
            }
            let Ok(address_lookup) = resolver.lookup_ip(host.as_str()).await else {
                continue;
            };
            let mut seen_addresses = HashSet::new();
            let addresses: Vec<_> = address_lookup
                .iter()
                .map(|ip| SocketAddr::new(ip, SMTP_PORT))
                .filter(|address| seen_addresses.insert(*address))
                .collect();
            if !addresses.is_empty() {
                endpoints.push(MxEndpoint { host, addresses });
            }
        }
        if endpoints.is_empty() {
            bail!("{domain} has no usable MX records or MX addresses");
        }

        Ok(Self {
            endpoints: Arc::new(endpoints),
            from: from.unwrap_or_else(|| format!("mprobe@{domain}")),
            helo: "mprobe.local".to_owned(),
            connect_timeout,
            command_timeout,
            disable_pipelining,
            consecutive_failures: Arc::new(AtomicUsize::new(0)),
            preferred_address: Arc::new(RwLock::new(None)),
        })
    }

    #[cfg(test)]
    fn for_test(address: SocketAddr, command_timeout: Duration) -> Self {
        Self {
            endpoints: Arc::new(vec![MxEndpoint {
                host: "mx.test".to_owned(),
                addresses: vec![address],
            }]),
            from: "mprobe@example.test".to_owned(),
            helo: "mprobe.local".to_owned(),
            connect_timeout: command_timeout,
            command_timeout,
            disable_pipelining: false,
            consecutive_failures: Arc::new(AtomicUsize::new(0)),
            preferred_address: Arc::new(RwLock::new(None)),
        }
    }

    pub fn mx_hosts(&self) -> impl Iterator<Item = &str> {
        self.endpoints.iter().map(|endpoint| endpoint.host.as_str())
    }

    pub async fn preflight(&self) -> Result<PreflightInfo> {
        let mut session = self.connect_session().await?;
        let info = PreflightInfo {
            mx: session.mx.clone(),
            address: session.address,
            pipelining: session.pipelining,
        };
        session.quit().await;
        Ok(info)
    }

    pub async fn probe_once(&self, email: String) -> ProbeResult {
        if !safe_recipient(&email) {
            return invalid_result(email);
        }
        let mut session = match self.connect_session().await {
            Ok(session) => session,
            Err(error) => return unknown_result(email, format!("{error:#}")),
        };
        let outcome = session.probe_batch(&self.from, vec![email]).await;
        session.quit().await;
        match outcome {
            Ok(mut outcome) => outcome.results.pop().expect("one result for one candidate"),
            Err(error) => unknown_result("catch-all check".to_owned(), format!("{error:#}")),
        }
    }

    pub async fn run_worker(
        &self,
        worker_id: usize,
        jobs: Arc<Mutex<mpsc::Receiver<Vec<String>>>>,
        results: mpsc::Sender<ProbeResult>,
        retries: usize,
    ) {
        let mut session: Option<SmtpSession> = None;
        while let Some(batch) = receive_batch(&jobs).await {
            if self.consecutive_failures.load(Ordering::Relaxed) >= CIRCUIT_BREAKER_FAILURES {
                if send_results(
                    &results,
                    batch.into_iter().map(|email| {
                        unknown_result(
                            email,
                            "SMTP circuit breaker open after repeated transport failures"
                                .to_owned(),
                        )
                    }),
                )
                .await
                .is_err()
                {
                    return;
                }
                continue;
            }

            let mut last_error = None;
            let mut pending = Some(batch);
            for attempt in 0..=retries {
                if session.is_none() {
                    match self.connect_session().await {
                        Ok(new_session) => session = Some(new_session),
                        Err(error) => {
                            last_error = Some(format!("{error:#}"));
                            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                if let Some(active_session) = session.as_mut() {
                    let candidates = pending.as_ref().expect("pending batch exists").clone();
                    match active_session.probe_batch(&self.from, candidates).await {
                        Ok(outcome) => {
                            self.consecutive_failures.store(0, Ordering::Relaxed);
                            if !outcome.reusable {
                                session = None;
                            }
                            if send_results(&results, outcome.results.into_iter())
                                .await
                                .is_err()
                            {
                                return;
                            }
                            pending = None;
                            break;
                        }
                        Err(error) => {
                            last_error = Some(format!("{error:#}"));
                            session = None;
                            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                if attempt < retries {
                    let backoff = 200_u64.saturating_mul(1_u64 << attempt.min(4));
                    let jitter = (worker_id as u64 * 37) % 100;
                    sleep(Duration::from_millis(backoff + jitter)).await;
                }
            }

            if let Some(unprocessed) = pending {
                let detail = last_error.unwrap_or_else(|| "SMTP worker failed".to_owned());
                if send_results(
                    &results,
                    unprocessed
                        .into_iter()
                        .map(|email| unknown_result(email, detail.clone())),
                )
                .await
                .is_err()
                {
                    return;
                }
            }
        }
        if let Some(mut active_session) = session {
            active_session.quit().await;
        }
    }

    async fn connect_session(&self) -> Result<SmtpSession> {
        let mut errors = Vec::new();
        let preferred = self
            .preferred_address
            .read()
            .ok()
            .and_then(|value| value.clone());
        if let Some((host, address)) = preferred.as_ref() {
            match self.connect_address(host, *address).await {
                Ok(session) => return Ok(session),
                Err(error) => errors.push(format!("{host} ({address}): {error:#}")),
            }
        }

        for endpoint in self.endpoints.iter() {
            for address in &endpoint.addresses {
                if preferred
                    .as_ref()
                    .is_some_and(|(host, preferred)| host == &endpoint.host && preferred == address)
                {
                    continue;
                }
                match self.connect_address(&endpoint.host, *address).await {
                    Ok(session) => return Ok(session),
                    Err(error) => errors.push(format!("{} ({address}): {error:#}", endpoint.host)),
                }
            }
        }
        bail!("could not establish an SMTP session: {}", errors.join("; "))
    }

    async fn connect_address(&self, host: &str, address: SocketAddr) -> Result<SmtpSession> {
        let stream = match timeout(self.connect_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => bail!("connection timed out"),
        };
        let _ = stream.set_nodelay(true);
        let mut session = SmtpSession {
            connection: BufReader::new(stream),
            mx: host.to_owned(),
            address,
            pipelining: false,
            command_timeout: self.command_timeout,
        };
        session
            .handshake(&self.helo, self.disable_pipelining)
            .await?;
        if let Ok(mut preferred) = self.preferred_address.write() {
            *preferred = Some((host.to_owned(), address));
        }
        Ok(session)
    }
}

struct SmtpSession {
    connection: BufReader<TcpStream>,
    mx: String,
    address: SocketAddr,
    pipelining: bool,
    command_timeout: Duration,
}

struct BatchOutcome {
    results: Vec<ProbeResult>,
    reusable: bool,
}

impl SmtpSession {
    async fn handshake(&mut self, helo: &str, disable_pipelining: bool) -> Result<()> {
        let greeting = self.response().await?;
        expect_class(&greeting, 2, "SMTP greeting")?;

        let ehlo = self.command(&format!("EHLO {helo}")).await?;
        if ehlo.code / 100 == 2 {
            self.pipelining = !disable_pipelining
                && ehlo.lines.iter().any(|line| {
                    line.split_whitespace()
                        .next()
                        .is_some_and(|value| value.eq_ignore_ascii_case("PIPELINING"))
                });
        } else {
            let response = self.command(&format!("HELO {helo}")).await?;
            expect_class(&response, 2, "HELO")?;
            self.pipelining = false;
        }
        Ok(())
    }

    async fn probe_batch(&mut self, from: &str, emails: Vec<String>) -> Result<BatchOutcome> {
        let mut results = Vec::with_capacity(emails.len());
        let valid: Vec<String> = emails
            .into_iter()
            .filter_map(|email| {
                if safe_recipient(&email) {
                    Some(email)
                } else {
                    results.push(invalid_result(email));
                    None
                }
            })
            .collect();
        if valid.is_empty() {
            return Ok(BatchOutcome {
                results,
                reusable: true,
            });
        }

        let mail = self.command(&format!("MAIL FROM:<{from}>")).await?;
        if mail.code / 100 != 2 {
            let detail = format!("MAIL FROM failed with {}: {}", mail.code, mail.message());
            results.extend(valid.into_iter().map(|email| ProbeResult {
                email,
                status: ProbeStatus::Unknown,
                code: Some(mail.code),
                mx: Some(self.mx.clone()),
                detail: detail.clone(),
            }));
            let reusable = mail.code != 421 && self.reset().await;
            return Ok(BatchOutcome { results, reusable });
        }

        if self.pipelining {
            let mut commands = String::new();
            for email in &valid {
                commands.push_str("RCPT TO:<");
                commands.push_str(email);
                commands.push_str(">\r\n");
            }
            self.write_raw(commands.as_bytes()).await?;
            for email in valid {
                let response = self.response().await?;
                results.push(result_from_response(email, &self.mx, response));
            }
        } else {
            for email in valid {
                let response = self.command(&format!("RCPT TO:<{email}>")).await?;
                results.push(result_from_response(email, &self.mx, response));
            }
        }

        let reusable = self.reset().await;
        Ok(BatchOutcome { results, reusable })
    }

    async fn reset(&mut self) -> bool {
        self.command("RSET")
            .await
            .is_ok_and(|response| response.code / 100 == 2)
    }

    async fn quit(&mut self) {
        let _ = self.command("QUIT").await;
    }

    async fn command(&mut self, command: &str) -> Result<Response> {
        let mut payload = String::with_capacity(command.len() + 2);
        payload.push_str(command);
        payload.push_str("\r\n");
        self.write_raw(payload.as_bytes()).await?;
        self.response().await
    }

    async fn write_raw(&mut self, payload: &[u8]) -> Result<()> {
        timeout(self.command_timeout, async {
            self.connection.get_mut().write_all(payload).await?;
            self.connection.get_mut().flush().await
        })
        .await
        .context("SMTP write timed out")??;
        Ok(())
    }

    async fn response(&mut self) -> Result<Response> {
        timeout(self.command_timeout, read_response(&mut self.connection))
            .await
            .context("SMTP response timed out")?
    }
}

#[derive(Debug)]
struct Response {
    code: u16,
    lines: Vec<String>,
}

impl Response {
    fn message(&self) -> String {
        self.lines.join(" ")
    }
}

async fn read_response(connection: &mut BufReader<TcpStream>) -> Result<Response> {
    let mut lines = Vec::new();
    let mut expected_code = None;
    loop {
        let mut line = String::new();
        let bytes = connection.read_line(&mut line).await?;
        if bytes == 0 {
            bail!("SMTP server closed the connection");
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 {
            bail!("malformed SMTP response: {trimmed:?}");
        }
        let code: u16 = trimmed
            .get(..3)
            .context("malformed non-ASCII SMTP response")?
            .parse()
            .map_err(|_| anyhow!("malformed SMTP response: {trimmed:?}"))?;
        if let Some(expected) = expected_code {
            if code != expected {
                bail!("inconsistent SMTP response codes");
            }
        } else {
            expected_code = Some(code);
        }
        lines.push(trimmed.get(4..).unwrap_or_default().to_owned());
        if trimmed.as_bytes().get(3) != Some(&b'-') {
            return Ok(Response { code, lines });
        }
    }
}

fn expect_class(response: &Response, class: u16, command: &str) -> Result<()> {
    if response.code / 100 != class {
        bail!(
            "{command} failed with {}: {}",
            response.code,
            response.message()
        );
    }
    Ok(())
}

fn result_from_response(email: String, mx: &str, response: Response) -> ProbeResult {
    let status = match response.code {
        250..=252 => ProbeStatus::Accepted,
        550 | 551 | 552 | 553 | 554 | 556 => ProbeStatus::Rejected,
        _ => ProbeStatus::Unknown,
    };
    ProbeResult {
        email,
        status,
        code: Some(response.code),
        mx: Some(mx.to_owned()),
        detail: response.message(),
    }
}

fn safe_recipient(value: &str) -> bool {
    value.len() <= 254
        && value.matches('@').count() == 1
        && !value.starts_with('@')
        && !value.ends_with('@')
        && !value.contains(['\r', '\n', '<', '>'])
        && !value.chars().any(char::is_control)
}

fn invalid_result(email: String) -> ProbeResult {
    ProbeResult {
        email,
        status: ProbeStatus::Invalid,
        code: None,
        mx: None,
        detail: "candidate is not a safe SMTP recipient address".to_owned(),
    }
}

fn unknown_result(email: String, detail: String) -> ProbeResult {
    ProbeResult {
        email,
        status: ProbeStatus::Unknown,
        code: None,
        mx: None,
        detail,
    }
}

async fn receive_batch(jobs: &Arc<Mutex<mpsc::Receiver<Vec<String>>>>) -> Option<Vec<String>> {
    jobs.lock().await.recv().await
}

async fn send_results(
    sender: &mpsc::Sender<ProbeResult>,
    results: impl Iterator<Item = ProbeResult>,
) -> Result<(), ()> {
    for result in results {
        if sender.send(result).await.is_err() {
            return Err(());
        }
    }
    Ok(())
}

fn validate_envelope_sender(value: &str) -> Result<()> {
    if !safe_recipient(value) {
        bail!("invalid --from email address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn validates_envelope_sender() {
        assert!(validate_envelope_sender("audit@example.com").is_ok());
        assert!(validate_envelope_sender("audit@example.com\r\nRCPT TO:<x@y.test>").is_err());
        assert!(validate_envelope_sender("missing-at.example.com").is_err());
    }

    #[tokio::test]
    async fn reuses_a_pipelined_session_across_batches() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            stream
                .get_mut()
                .write_all(b"220 mx.test ready\r\n")
                .await
                .unwrap();
            let mut rcpt_count = 0;
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let response: &[u8] = if line.starts_with("EHLO") {
                    b"250-mx.test\r\n250 PIPELINING\r\n"
                } else if line.starts_with("MAIL FROM") || line.starts_with("RSET") {
                    b"250 OK\r\n"
                } else if line.starts_with("RCPT TO") {
                    rcpt_count += 1;
                    if line.contains("missing") {
                        b"550 no such user\r\n"
                    } else {
                        b"250 recipient accepted\r\n"
                    }
                } else if line.starts_with("QUIT") {
                    stream.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"500 unexpected\r\n"
                };
                stream.get_mut().write_all(response).await.unwrap();
                stream.get_mut().flush().await.unwrap();
            }
            rcpt_count
        });

        let prober = SmtpProber::for_test(address, Duration::from_secs(1));
        let mut session = prober.connect_session().await.unwrap();
        assert!(session.pipelining);
        let first = session
            .probe_batch(
                &prober.from,
                vec!["one@example.test".into(), "missing@example.test".into()],
            )
            .await
            .unwrap();
        let second = session
            .probe_batch(&prober.from, vec!["two@example.test".into()])
            .await
            .unwrap();
        assert!(first.reusable && second.reusable);
        assert_eq!(first.results[0].status, ProbeStatus::Accepted);
        assert_eq!(first.results[1].status, ProbeStatus::Rejected);
        assert_eq!(second.results[0].status, ProbeStatus::Accepted);
        session.quit().await;
        assert_eq!(server.await.unwrap(), 3);
    }
}
