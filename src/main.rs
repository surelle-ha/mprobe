use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufWriter, IsTerminal, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anstyle::{AnsiColor, Style};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use idna::domain_to_ascii;
use serde::Serialize;
use tokio::sync::{Mutex, mpsc};

use mprobe::{
    candidate::{CandidateIter, candidate_count},
    probe::{ProbeResult, ProbeStatus, SmtpProber},
    template::Template,
    wordlists,
};

const DEFAULT_LIMIT: usize = 1_000;
const BANNER: &str = r#" __  __ ____  ____   ___  ____  _____
|  \/  |  _ \|  _ \ / _ \| __ )| ____|
| |\/| | |_) | |_) | | | |  _ \|  _|
| |  | |  __/|  _ <| |_| | |_) | |___
|_|  |_|_|   |_| \_\ \___/|____/|_____|"#;

#[derive(Debug, Parser)]
#[command(
    name = "mprobe",
    version,
    about = "Generate and optionally probe email addresses from combination templates",
    long_about = "mprobe combines built-in or external wordlists into email candidates. Generation is offline by default; use --probe to check candidates with the target domain's SMTP server.",
    after_help = "TEMPLATE EXAMPLES:\n  '$fname.$lname'       john.doe@example.com\n  '$fname_$lname'       john_doe@example.com\n  '${fname}-$lname'     john-doe@example.com\n  '$role@$domain'       admin@example.com\n\nQuote templates with single quotes so your shell does not expand $variables.\nOnly probe systems you own or have permission to assess."
)]
struct Cli {
    /// Show bundled wordlists and their variables
    #[arg(short = 's', long = "show-wordlists")]
    show_wordlists: bool,

    /// Target email domain
    #[arg(short = 't', long = "target", value_name = "DOMAIN")]
    target: Option<String>,

    /// Combination template, such as '$fname.$lname'
    #[arg(short = 'c', long = "combination", value_name = "TEMPLATE")]
    combination: Option<String>,

    /// Explicit external wordlist mapping (repeatable), such as fname=staff.txt
    #[arg(short = 'w', long = "wordlist", value_name = "NAME=FILE")]
    wordlists: Vec<String>,

    /// Replace template wordlists in first-appearance order
    #[arg(value_name = "WORDLIST")]
    positional_wordlists: Vec<PathBuf>,

    /// Actively check candidates through the target's MX servers
    #[arg(short = 'p', long)]
    probe: bool,

    /// Maximum candidates to generate/check; 0 means all
    #[arg(short = 'l', long, default_value_t = DEFAULT_LIMIT)]
    limit: usize,

    /// Persistent SMTP connections (also accepts --concurrency)
    #[arg(long, visible_alias = "concurrency", default_value_t = 4)]
    connections: usize,

    /// Recipients checked per SMTP transaction
    #[arg(long, default_value_t = 25)]
    batch_size: usize,

    /// TCP connection timeout in seconds
    #[arg(long, default_value_t = 3)]
    connect_timeout: u64,

    /// Per-command SMTP timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Reconnect attempts after a transport failure
    #[arg(long, default_value_t = 1)]
    retries: usize,

    /// Disable automatic SMTP PIPELINING
    #[arg(long)]
    no_pipelining: bool,

    /// Envelope sender used during SMTP checks
    #[arg(long, value_name = "EMAIL")]
    from: Option<String>,

    /// Skip the preliminary random-address catch-all check
    #[arg(long)]
    no_catch_all_check: bool,

    /// Output encoding
    #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,

    /// Write results to a file instead of stdout
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Suppress informational messages on stderr
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Terminal color behavior
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    /// Hide the interactive startup banner
    #[arg(long)]
    no_banner: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Plain,
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    fn enabled(self, terminal: bool) -> bool {
        match self {
            Self::Auto => terminal,
            Self::Always => true,
            Self::Never => false,
        }
    }
}

#[derive(Clone, Copy)]
struct Theme {
    enabled: bool,
}

impl Theme {
    fn stderr(mode: ColorMode) -> Self {
        Self {
            enabled: mode.enabled(io::stderr().is_terminal()),
        }
    }

    fn stdout(mode: ColorMode) -> Self {
        Self {
            enabled: mode.enabled(io::stdout().is_terminal()),
        }
    }

    fn plain() -> Self {
        Self { enabled: false }
    }

    fn paint(self, style: Style, value: impl std::fmt::Display) -> String {
        if self.enabled {
            format!("{style}{value}{style:#}")
        } else {
            value.to_string()
        }
    }

    fn info(self, value: impl std::fmt::Display) -> String {
        self.paint(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightCyan.into())),
            value,
        )
    }

    fn warning(self, value: impl std::fmt::Display) -> String {
        self.paint(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightYellow.into())),
            value,
        )
    }

    fn error(self, value: impl std::fmt::Display) -> String {
        self.paint(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightRed.into())),
            value,
        )
    }

    fn success(self, value: impl std::fmt::Display) -> String {
        self.paint(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightGreen.into())),
            value,
        )
    }

    fn accent(self, value: impl std::fmt::Display) -> String {
        self.paint(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightMagenta.into())),
            value,
        )
    }

    fn bold(self, value: impl std::fmt::Display) -> String {
        self.paint(Style::new().bold(), value)
    }

    fn secondary(self, value: impl std::fmt::Display) -> String {
        self.paint(Style::new().italic().dimmed(), value)
    }
}

#[derive(Serialize)]
struct GeneratedResult<'a> {
    email: &'a str,
}

#[derive(Default)]
struct ProbeStats {
    accepted_by_mx: usize,
    recipient_rejected: usize,
    temporary_failure: usize,
    policy_blocked: usize,
    permanent_failure: usize,
    inconclusive: usize,
    invalid: usize,
}

impl ProbeStats {
    fn record(&mut self, status: ProbeStatus) {
        match status {
            ProbeStatus::AcceptedByMx => self.accepted_by_mx += 1,
            ProbeStatus::RecipientRejected => self.recipient_rejected += 1,
            ProbeStatus::TemporaryFailure => self.temporary_failure += 1,
            ProbeStatus::PolicyBlocked => self.policy_blocked += 1,
            ProbeStatus::PermanentFailure => self.permanent_failure += 1,
            ProbeStatus::Inconclusive => self.inconclusive += 1,
            ProbeStatus::Invalid => self.invalid += 1,
        }
    }

    fn total(&self) -> usize {
        self.accepted_by_mx
            + self.recipient_rejected
            + self.temporary_failure
            + self.policy_blocked
            + self.permanent_failure
            + self.inconclusive
            + self.invalid
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let theme = Theme::stderr(cli.color);
    if let Err(error) = run(cli).await {
        eprintln!(
            "{} {}",
            theme.error("error:"),
            theme.secondary(format!("{error:#}"))
        );
        std::process::exit(2);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let stderr_theme = Theme::stderr(cli.color);
    let stdout_theme = Theme::stdout(cli.color);
    if !cli.quiet && io::stderr().is_terminal() {
        eprintln!();
        if !cli.no_banner {
            eprintln!("{}", stderr_theme.info(BANNER));
            eprintln!(
                "  {} {}",
                stderr_theme.bold(format!("mprobe v{}", env!("CARGO_PKG_VERSION"))),
                stderr_theme.secondary("template-driven SMTP enumeration")
            );
            eprintln!();
        }
    }
    if !(1..=64).contains(&cli.connections) {
        bail!("--connections must be between 1 and 64");
    }
    if !(1..=100).contains(&cli.batch_size) {
        bail!("--batch-size must be between 1 and 100");
    }
    if !(1..=120).contains(&cli.connect_timeout) {
        bail!("--connect-timeout must be between 1 and 120 seconds");
    }
    if !(1..=120).contains(&cli.timeout) {
        bail!("--timeout must be between 1 and 120 seconds");
    }
    if cli.retries > 5 {
        bail!("--retries must be between 0 and 5");
    }

    if cli.show_wordlists {
        show_wordlists(stdout_theme);
        if cli.target.is_none() && cli.combination.is_none() {
            return Ok(());
        }
    }

    let target = validate_domain(
        cli.target
            .as_deref()
            .context("--target <DOMAIN> is required (unless only using --show-wordlists)")?,
    )?;
    let combination = cli
        .combination
        .as_deref()
        .context("--combination <TEMPLATE> is required")?;

    let named: Vec<_> = cli
        .wordlists
        .iter()
        .map(|value| wordlists::parse_named(value))
        .collect::<Result<_>>()?;
    let available: HashSet<String> = wordlists::builtin_names()
        .map(str::to_owned)
        .chain(named.iter().map(|(name, _)| name.clone()))
        .collect();
    let template = Template::parse(combination, available)?;
    let template_order: Vec<String> = template.list_variables().map(str::to_owned).collect();
    let lists = wordlists::load(&named, &cli.positional_wordlists, &template_order)?;
    let total = candidate_count(&template, &lists)?;
    let selected = if cli.limit == 0 {
        total
    } else {
        total.min(cli.limit as u128)
    };

    if !cli.quiet {
        eprintln!(
            "{} template uses {} candidate combination{}; processing {} {}",
            stderr_theme.info("[i]"),
            stderr_theme.bold(format_count(total)),
            if total == 1 { "" } else { "s" },
            stderr_theme.bold(format_count(selected)),
            if selected < total {
                stderr_theme.secondary("(change --limit, or use --limit 0 for all)")
            } else {
                String::new()
            }
        );
    }

    let writer: Box<dyn Write + Send> = match &cli.output {
        Some(path) => {
            Box::new(BufWriter::new(File::create(path).with_context(|| {
                format!("could not create {}", path.display())
            })?))
        }
        None => Box::new(BufWriter::new(io::stdout())),
    };

    let candidates = CandidateIter::new(&template, &target, &lists)?.take(if cli.limit == 0 {
        usize::MAX
    } else {
        cli.limit
    });
    if cli.probe {
        probe_candidates(candidates, &target, &cli, writer).await
    } else {
        write_generated(candidates, cli.format, writer)
    }
}

fn show_wordlists(theme: Theme) {
    println!(
        "{}",
        theme.bold("Bundled wordlists (compiled into the binary):")
    );
    for (name, path, count) in wordlists::builtin_metadata() {
        println!(
            "  {} {count:>6} entries  {}",
            theme.info(format!("${name:<8}")),
            theme.secondary(path)
        );
    }
    println!();
    println!("{}", theme.bold("External lists:"));
    println!("  mprobe -t example.com -c '$fname.$lname' fname.txt lname.txt");
    println!("  mprobe -t example.com -c '$fname.$lname' -w fname=staff.txt -w lname=surnames.txt");
}

fn write_generated(
    candidates: impl Iterator<Item = Result<String>>,
    format: OutputFormat,
    mut writer: Box<dyn Write + Send>,
) -> Result<()> {
    if matches!(format, OutputFormat::Csv) {
        writeln!(writer, "email")?;
    }
    for candidate in candidates {
        let candidate = candidate?;
        match format {
            OutputFormat::Plain => writeln!(writer, "{candidate}")?,
            OutputFormat::Jsonl => writeln!(
                writer,
                "{}",
                serde_json::to_string(&GeneratedResult { email: &candidate })?
            )?,
            OutputFormat::Csv => writeln!(writer, "{}", csv_escape(&candidate))?,
        }
    }
    writer.flush()?;
    Ok(())
}

async fn probe_candidates(
    candidates: impl Iterator<Item = Result<String>>,
    target: &str,
    cli: &Cli,
    writer: Box<dyn Write + Send>,
) -> Result<()> {
    let stderr_theme = Theme::stderr(cli.color);
    let result_theme = if cli.output.is_none() && matches!(cli.format, OutputFormat::Plain) {
        Theme::stdout(cli.color)
    } else {
        Theme::plain()
    };
    let prober = Arc::new(
        SmtpProber::discover(
            target,
            cli.from.clone(),
            Duration::from_secs(cli.connect_timeout),
            Duration::from_secs(cli.timeout),
            cli.no_pipelining,
        )
        .await?,
    );
    if !cli.quiet {
        eprintln!(
            "{} MX hosts: {}",
            stderr_theme.info("[i]"),
            stderr_theme.bold(prober.mx_hosts().collect::<Vec<_>>().join(", "))
        );
    }

    let preflight = prober
        .preflight()
        .await
        .context("SMTP preflight failed; no candidate checks were started")?;
    if !cli.quiet {
        eprintln!(
            "{} connected to {} {} — PIPELINING {}",
            stderr_theme.info("[i]"),
            stderr_theme.bold(&preflight.mx),
            stderr_theme.secondary(format!("({})", preflight.address)),
            if preflight.pipelining {
                stderr_theme.success("enabled")
            } else {
                stderr_theme.warning("unavailable")
            }
        );
    }

    if !cli.no_catch_all_check {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let catch_all = prober
            .probe_once(format!("mprobe-{nonce:x}@{target}"))
            .await;
        match catch_all.status {
            ProbeStatus::AcceptedByMx => eprintln!(
                "{} the domain accepted a random address; {}",
                stderr_theme.warning("[!]"),
                stderr_theme.secondary("accepted_by_mx results may be catch-all responses")
            ),
            ProbeStatus::RecipientRejected => {}
            _ if !cli.quiet => eprintln!(
                "{} catch-all status could not be determined: {}",
                stderr_theme.info("[i]"),
                stderr_theme.secondary(&catch_all.detail)
            ),
            _ => {}
        }
    }

    if !cli.quiet {
        eprintln!(
            "{} fast probe: {} persistent connection{}, batches of {}, {} reconnect attempt{}",
            stderr_theme.info("[i]"),
            stderr_theme.bold(cli.connections),
            if cli.connections == 1 { "" } else { "s" },
            stderr_theme.bold(cli.batch_size),
            stderr_theme.bold(cli.retries),
            if cli.retries == 1 { "" } else { "s" }
        );
    }

    let started = Instant::now();
    let job_capacity = cli.connections.saturating_mul(2).max(1);
    let result_capacity = cli
        .connections
        .saturating_mul(cli.batch_size)
        .saturating_mul(2)
        .max(1);
    let (job_sender, job_receiver) = mpsc::channel::<Vec<String>>(job_capacity);
    let jobs = Arc::new(Mutex::new(job_receiver));
    let (result_sender, result_receiver) = mpsc::channel::<ProbeResult>(result_capacity);

    let writer_format = cli.format;
    let writer_task = tokio::spawn(write_probe_results(
        writer,
        writer_format,
        result_theme,
        result_receiver,
    ));

    let mut workers = Vec::with_capacity(cli.connections);
    for worker_id in 0..cli.connections {
        let prober = Arc::clone(&prober);
        let jobs = Arc::clone(&jobs);
        let results = result_sender.clone();
        let retries = cli.retries;
        workers.push(tokio::spawn(async move {
            prober.run_worker(worker_id, jobs, results, retries).await;
        }));
    }
    drop(result_sender);

    let mut producer_error = None;
    let mut batch = Vec::with_capacity(cli.batch_size);
    for candidate in candidates {
        match candidate {
            Ok(candidate) => batch.push(candidate),
            Err(error) => {
                producer_error = Some(error);
                break;
            }
        }
        if batch.len() == cli.batch_size {
            let ready = std::mem::replace(&mut batch, Vec::with_capacity(cli.batch_size));
            if job_sender.send(ready).await.is_err() {
                producer_error = Some(anyhow!("all SMTP workers stopped unexpectedly"));
                break;
            }
        }
    }
    if producer_error.is_none() && !batch.is_empty() && job_sender.send(batch).await.is_err() {
        producer_error = Some(anyhow!("all SMTP workers stopped unexpectedly"));
    }
    drop(job_sender);

    let mut worker_error = None;
    for worker in workers {
        if let Err(error) = worker.await {
            worker_error = Some(anyhow!("SMTP worker task failed: {error}"));
        }
    }

    let stats = writer_task.await.context("result writer task failed")??;
    if let Some(error) = producer_error.or(worker_error) {
        return Err(error);
    }

    if !cli.quiet {
        let elapsed = started.elapsed();
        let rate = if elapsed.is_zero() {
            stats.total() as f64
        } else {
            stats.total() as f64 / elapsed.as_secs_f64()
        };
        eprintln!(
            "{} completed {} checks in {} ({}): {} accepted by MX, {} recipient rejected, {} temporary, {} policy blocked, {} permanent, {} inconclusive, {} invalid",
            stderr_theme.info("[i]"),
            stderr_theme.bold(stats.total()),
            stderr_theme.bold(format!("{elapsed:.2?}")),
            stderr_theme.secondary(format!("{rate:.1}/s")),
            stderr_theme.success(stats.accepted_by_mx),
            stderr_theme.error(stats.recipient_rejected),
            stderr_theme.warning(stats.temporary_failure),
            stderr_theme.warning(stats.policy_blocked),
            stderr_theme.error(stats.permanent_failure),
            stderr_theme.warning(stats.inconclusive),
            stderr_theme.accent(stats.invalid)
        );
    }
    Ok(())
}

async fn write_probe_results(
    mut writer: Box<dyn Write + Send>,
    format: OutputFormat,
    theme: Theme,
    mut results: mpsc::Receiver<ProbeResult>,
) -> Result<ProbeStats> {
    if matches!(format, OutputFormat::Csv) {
        writeln!(writer, "email,status,code,enhanced_code,mx,detail")?;
    }
    let mut stats = ProbeStats::default();
    let mut buffered = 0_usize;
    let mut flush_interval = tokio::time::interval(Duration::from_secs(1));
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_interval.tick().await;

    loop {
        tokio::select! {
            result = results.recv() => {
                let Some(result) = result else { break };
                stats.record(result.status);
                write_probe_result(&mut writer, format, theme, &result)?;
                buffered += 1;
                if buffered >= 256 {
                    writer.flush()?;
                    buffered = 0;
                }
            }
            _ = flush_interval.tick(), if buffered > 0 => {
                writer.flush()?;
                buffered = 0;
            }
        }
    }
    writer.flush()?;
    Ok(stats)
}

fn write_probe_result(
    writer: &mut dyn Write,
    format: OutputFormat,
    theme: Theme,
    result: &ProbeResult,
) -> Result<()> {
    match format {
        OutputFormat::Plain => {
            let status = match result.status {
                ProbeStatus::AcceptedByMx => theme.success(format!("[{}]", result.status)),
                ProbeStatus::RecipientRejected | ProbeStatus::PermanentFailure => {
                    theme.error(format!("[{}]", result.status))
                }
                ProbeStatus::TemporaryFailure
                | ProbeStatus::PolicyBlocked
                | ProbeStatus::Inconclusive => theme.warning(format!("[{}]", result.status)),
                ProbeStatus::Invalid => theme.accent(format!("[{}]", result.status)),
            };
            write!(writer, "{status} {}", result.email)?;
            if let Some(code) = result.code {
                write!(writer, " smtp={code}")?;
            }
            if let Some(enhanced_code) = result.enhanced_code.as_deref() {
                write!(writer, " enhanced={enhanced_code}")?;
            }
            writeln!(writer)?;
        }
        OutputFormat::Jsonl => writeln!(writer, "{}", serde_json::to_string(result)?)?,
        OutputFormat::Csv => writeln!(
            writer,
            "{},{},{},{},{},{}",
            csv_escape(&result.email),
            result.status,
            result
                .code
                .map(|value| value.to_string())
                .unwrap_or_default(),
            result.enhanced_code.as_deref().unwrap_or_default(),
            csv_escape(result.mx.as_deref().unwrap_or_default()),
            csv_escape(&result.detail)
        )?,
    }
    Ok(())
}

fn csv_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn validate_domain(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('.');
    if value.contains('@') || value.contains('/') || value.contains(':') || value.is_empty() {
        bail!("invalid target domain '{value}'");
    }
    let ascii = domain_to_ascii(value).context("target is not a valid domain name")?;
    if ascii.len() > 253
        || !ascii.contains('.')
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
    {
        bail!("invalid target domain '{value}'");
    }
    Ok(ascii.to_lowercase())
}

fn format_count(value: u128) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(ch);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_domains() {
        assert_eq!(validate_domain("Example.COM.").unwrap(), "example.com");
        assert!(validate_domain("https://example.com").is_err());
        assert!(validate_domain("localhost").is_err());
    }

    #[test]
    fn escapes_csv_fields() {
        assert_eq!(csv_escape("a,\"b"), "\"a,\"\"b\"");
    }

    #[test]
    fn writes_observed_codes_in_plain_and_csv_formats() {
        let result = ProbeResult {
            email: "person@example.test".to_owned(),
            status: ProbeStatus::PolicyBlocked,
            code: Some(550),
            enhanced_code: Some("5.7.1".to_owned()),
            mx: Some("mx.example.test".to_owned()),
            detail: "blocked by policy".to_owned(),
        };

        let mut plain = Vec::new();
        write_probe_result(&mut plain, OutputFormat::Plain, Theme::plain(), &result).unwrap();
        assert_eq!(
            String::from_utf8(plain).unwrap(),
            "[policy_blocked] person@example.test smtp=550 enhanced=5.7.1\n"
        );

        let mut csv = Vec::new();
        write_probe_result(&mut csv, OutputFormat::Csv, Theme::plain(), &result).unwrap();
        assert_eq!(
            String::from_utf8(csv).unwrap(),
            "\"person@example.test\",policy_blocked,550,5.7.1,\"mx.example.test\",\"blocked by policy\"\n"
        );
    }
}
