use std::fs;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use neuron_encrypt_core::crypto::{self, ProgressReporter, ThrottledReporter};
use neuron_encrypt_core::error::CryptoError;
use neuron_encrypt_core::utils::{constant_time_eq, is_vx2_file, HumanBytes};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

#[derive(Parser)]
#[command(
    name = "neuron-encrypt-cli",
    version = concat!(env!("CARGO_PKG_VERSION"), " (git: ", env!("GIT_HASH"), ")"),
    about = "Command-line file encryption using AES-256-GCM-SIV + Argon2id",
    long_about = "Encrypt or decrypt files from the terminal. \
Supports piping, progress bars, JSON output, and silent mode for scripts.",
    after_help = r#"EXAMPLES:
  # Encrypt a file (prompts for passphrase)
  neuron-encrypt-cli encrypt -i secret.pdf

  # Encrypt with custom output
  neuron-encrypt-cli encrypt -i secret.pdf -o vault/secret.vx2

  # Decrypt (prompts for passphrase)
  neuron-encrypt-cli decrypt -i secret.vx2

  # Decrypt to custom path
  neuron-encrypt-cli decrypt -i secret.vx2 -o recovered.pdf

  # Quiet mode (scripts)
  neuron-encrypt-cli encrypt -i secret.pdf -q
  neuron-encrypt-cli encrypt -i secret.pdf --password-file /run/secrets/key

  # Pipe passphrase via env var
  NEURON_PASSWORD="mypass" neuron-encrypt-cli encrypt -i secret.pdf

  # Pipe data through CLI
  cat backup.tar.gz | neuron-encrypt-cli decrypt -i - -o backup.tar.gz

  # JSON output for automation
  neuron-encrypt-cli encrypt -i secret.pdf --json

  # Generate shell completions
  neuron-encrypt-cli completions bash > ~/.local/share/bash-completion/neuron-encrypt-cli
"#
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress all non-error output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable progress bar (implies --quiet if not --json)
    #[arg(long, global = true)]
    no_progress: bool,

    /// Emit structured JSON output for automation
    #[arg(long, global = true)]
    json: bool,

    /// Read passphrase from file (useful for CI/CD)
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,

    /// Overwrite existing output files
    #[arg(short = 'F', long, global = true)]
    force: bool,

    /// Generate shell completions (bash, zsh, fish, powershell, elvish)
    #[arg(long)]
    completions: Option<Shell>,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file
    Encrypt {
        /// Input file path (use "-" for stdin)
        #[arg(short, long)]
        input: String,

        /// Output file path (use "-" for stdout, defaults to input.vx2)
        #[arg(short, long)]
        output: Option<String>,
        /// Skip passphrase confirmation prompt (for non-interactive/script use)
        #[arg(long, default_value_t = false)]
        no_confirm: bool,
    },
    /// Decrypt a file
    Decrypt {
        /// Input .vx2 file path (use "-" for stdin)
        #[arg(short, long)]
        input: String,

        /// Output file path (use "-" for stdout, defaults to original name)
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn read_password(
    password_file: &Option<PathBuf>,
) -> Result<Zeroizing<Vec<u8>>, (ExitCode, String)> {
    if let Some(path) = password_file {
        // Wrap in Zeroizing immediately so even on UTF-8 failure the bytes are zeroed.
        // Returns Vec<u8> (not String) to support binary key files.
        let mut bytes = Zeroizing::new(fs::read(path).map_err(|e| {
            (
                ExitCode::BadInput,
                format!("Cannot read password file: {e}"),
            )
        })?);
        // Strip trailing \r\n
        while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
            bytes.pop();
        }
        return Ok(bytes);
    }

    if let Ok(pw) = std::env::var("NEURON_PASSWORD") {
        eprintln!(
            "[WARN] NEURON_PASSWORD is set: password is visible in /proc/<pid>/environ \n       and may appear in shell history or process monitors."
        );
        eprintln!("[WARN] Prefer --password-file with a 0600-permission file for sensitive use.");
        return Ok(Zeroizing::new(pw.into_bytes()));
    }

    loop {
        match rpassword::prompt_password("Enter passphrase: ") {
            Ok(pw) => {
                if pw.is_empty() {
                    eprintln!("Error: Passphrase cannot be empty.");
                    continue;
                }
                return Ok(Zeroizing::new(pw.into_bytes()));
            }
            Err(e) => {
                return Err((ExitCode::BadInput, format!("Error reading passphrase: {e}")));
            }
        }
    }
}

fn read_password_confirmed(
    password_file: &Option<PathBuf>,
) -> Result<Zeroizing<Vec<u8>>, (ExitCode, String)> {
    let pass1 = read_password(password_file)?;
    let pass2 = loop {
        match rpassword::prompt_password("Confirm passphrase: ") {
            Ok(pw) => {
                if pw.is_empty() {
                    eprintln!("Error: Passphrase cannot be empty.");
                    continue;
                }
                break Zeroizing::new(pw.into_bytes());
            }
            Err(e) => return Err((ExitCode::BadInput, format!("Error reading passphrase: {e}"))),
        }
    };
    if !constant_time_eq(pass1.as_slice(), pass2.as_slice()) {
        return Err((ExitCode::BadInput, "Passphrases do not match".to_owned()));
    }
    Ok(pass1)
}

struct IndProgress {
    pb: ProgressBar,
    total_bytes: u64,
}

impl IndProgress {
    fn new(total: Option<u64>, action: &str) -> Self {
        let pb = ProgressBar::new(total.unwrap_or(0));

        let style = if total.is_some() {
            ProgressStyle::with_template(
                "[{bar:10.cyan/blue}] {percent}% | {msg} | {bytes:>7}/{total_bytes:7} | {bytes_per_sec} | ETA {eta}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .with_key("bytes_per_sec", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                let _ = write!(w, "{}/s", HumanBytes(state.pos()));
            })
            .progress_chars("##-")
        } else {
            ProgressStyle::with_template("{spinner} | {msg} | {bytes} | {bytes_per_sec}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .with_key(
                    "bytes_per_sec",
                    |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                        let _ = write!(w, "{}/s", HumanBytes(state.pos()));
                    },
                )
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        };

        pb.set_style(style);
        pb.set_message(action.to_owned());

        Self {
            pb,
            total_bytes: total.unwrap_or(0),
        }
    }
}

/// Implements [`ProgressReporter`] for the terminal progress bar.
///
/// # Progress range
///
/// The `report(progress, …)` callback accepts `progress` in `[0.0, 1.0]`:
/// - `0.0` – `0.10` — KDF phase (bar stays near 0 %).
/// - `0.10` – `0.95` — encryption/decryption (bar maps 0 % → 100 %).
/// - `0.95` – `1.0` — finalization / cleanup.
///
/// Values outside `[0.0, 1.0]` are silently clamped, and the bar
/// position is capped at `total_bytes` to prevent exceeding 100 %.
impl ProgressReporter for IndProgress {
    fn report(&self, progress: f32, message: &str) {
        let clamped = progress.clamp(0.0, 1.0);
        let bytes = if self.total_bytes > 0 {
            let fraction = ((clamped - 0.10) / 0.85).clamp(0.0, 1.0);
            (fraction * self.total_bytes as f32) as u64
        } else {
            0
        };

        if self.total_bytes > 0 {
            self.pb.set_position(bytes.min(self.total_bytes));
        }
        self.pb.set_message(message.to_owned());
    }
}

impl Drop for IndProgress {
    fn drop(&mut self) {
        self.pb.finish_with_message("Complete");
    }
}

struct QuietReporter;
impl ProgressReporter for QuietReporter {
    fn report(&self, _progress: f32, _message: &str) {}
}

#[derive(Serialize)]
struct JsonResult {
    status: String,
    output_path: Option<String>,
    bytes_processed: Option<u64>,
    duration_ms: u128,
    sha256: Option<String>,
    error: Option<String>,
}

#[repr(i32)]
enum ExitCode {
    Success = 0,
    RuntimeError = 1,
    BadInput = 2,
    WrongPassword = 3,
}

fn resolve_output(input_path: &Path, mode: &str, output_arg: &Option<String>) -> PathBuf {
    if let Some(out) = output_arg {
        if out == "-" {
            return PathBuf::from("-");
        }
        return PathBuf::from(out);
    }

    match mode {
        "encrypt" => input_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(crypto::default_encrypt_output_name(input_path)),
        "decrypt" => input_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(crypto::default_decrypt_output_name(input_path)),
        _ => input_path.to_path_buf(),
    }
}

#[cfg(target_os = "windows")]
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

#[cfg(not(target_os = "windows"))]
fn same_path(a: &Path, b: &Path) -> bool {
    a == b
}

fn validate_output_path(
    input_path: &Path,
    output_path: &Path,
    force: bool,
    json: bool,
    start: &Instant,
) -> Result<(), (ExitCode, String)> {
    if !output_path.exists() {
        return Ok(());
    }

    if !force {
        let msg = format!(
            "Output file already exists: {}. Use --force to overwrite.",
            output_path.display()
        );
        emit_json_result(json, start, Some(output_path.display().to_string()), None, None, "error", Some(msg.clone()));
        eprintln!("Error: {msg}");
        return Err((ExitCode::BadInput, msg));
    }

    let input = fs::canonicalize(input_path).map_err(|e| {
        (
            ExitCode::BadInput,
            format!("Cannot resolve input path: {e}"),
        )
    })?;
    let output = fs::canonicalize(output_path).map_err(|e| {
        (
            ExitCode::BadInput,
            format!("Cannot resolve output path: {e}"),
        )
    })?;

    if same_path(&input, &output) {
        let msg = "Refusing to overwrite the input file in place.".to_owned();
        emit_json_result(json, start, Some(output_path.display().to_string()), None, None, "error", Some(msg.clone()));
        eprintln!("Error: {msg}");
        return Err((ExitCode::BadInput, msg));
    }

    if output_path.is_dir() {
        let msg = format!("Output path is a directory: {}", output_path.display());
        emit_json_result(json, start, Some(output_path.display().to_string()), None, None, "error", Some(msg.clone()));
        eprintln!("Error: {msg}");
        return Err((ExitCode::BadInput, msg));
    }

    fs::remove_file(output_path).map_err(|e| {
        (
            ExitCode::RuntimeError,
            format!("Cannot remove existing output file: {e}"),
        )
    })
}

fn emit_json(result: &JsonResult) {
    match serde_json::to_string(result) {
        Ok(json) => println!("{json}"),
        Err(error) => eprintln!("Error: failed to serialize JSON output: {error}"),
    }
}

fn err_json(start: &Instant, output: Option<String>, msg: &str) -> JsonResult {
    JsonResult {
        status: "error".into(),
        output_path: output,
        bytes_processed: None,
        duration_ms: start.elapsed().as_millis(),
        sha256: None,
        error: Some(msg.into()),
    }
}

fn emit_error_json(json: bool, start: &Instant, output: Option<String>, msg: &str) {
    if json {
        emit_json(&err_json(start, output, msg));
    }
}

fn emit_success_json(
    json: bool,
    start: &Instant,
    output: Option<String>,
    bytes_processed: Option<u64>,
    sha256: Option<String>,
) {
    if json {
        emit_json(&JsonResult {
            status: "success".into(),
            output_path: output,
            bytes_processed,
            duration_ms: start.elapsed().as_millis(),
            sha256,
            error: None,
        });
    }
}

fn emit_json_result(
    json: bool,
    start: &Instant,
    output: Option<String>,
    bytes_processed: Option<u64>,
    sha256: Option<String>,
    status: &str,
    error: Option<String>,
) {
    if json {
        emit_json(&JsonResult {
            status: status.to_string(),
            output_path: output,
            bytes_processed,
            duration_ms: start.elapsed().as_millis(),
            sha256,
            error,
        });
    }
}

fn compute_sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new([0u8; 65536]);
    loop {
        let n = file.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    Ok(format!("{result:x}"))
}

fn setup_reporter(show_progress: bool, source_size: Option<u64>) -> Box<dyn ProgressReporter> {
    if show_progress {
        Box::new(IndProgress::new(source_size, "Deriving key..."))
    } else {
        Box::new(QuietReporter)
    }
}

fn run_file(
    cli: &Cli,
    start: Instant,
    password: &[u8],
    mode: &str,
    input_str: &str,
    output_str: &Option<String>,
) -> Result<(), ExitCode> {
    let input_path = PathBuf::from(input_str);
    if !input_path.exists() {
        let msg = format!("Input file not found: {}", input_path.display());
        emit_error_json(cli.json, &start, None, &msg);
        eprintln!("Error: {msg}");
        return Err(ExitCode::BadInput);
    }

    if mode == "encrypt" && is_vx2_file(&input_path) && !cli.force {
        let msg = "Input file appears to be already encrypted (.vx2). Encrypting again will produce .vx2.vx2. Use --force to proceed.".to_owned();
        emit_error_json(cli.json, &start, None, &msg);
        eprintln!("Warning: {msg}");
        return Err(ExitCode::BadInput);
    }

    let source_size = fs::metadata(&input_path).ok().map(|m| m.len());
    let output_path = resolve_output(&input_path, mode, output_str);

    if let Err((code, msg)) = validate_output_path(&input_path, &output_path, cli.force, cli.json, &start) {
        emit_error_json(cli.json, &start, Some(output_path.display().to_string()), &msg);
        eprintln!("Error: {msg}");
        return Err(code);
    }

    if !cli.quiet && !cli.json {
        let action = if mode == "encrypt" { "Encrypting" } else { "Decrypting" };
        let total = source_size.unwrap_or(0);
        eprintln!(
            "{} {}{} → {}",
            action,
            input_path.display(),
            if total > 0 {
                format!(" ({})", HumanBytes(total))
            } else {
                String::new()
            },
            output_path.display()
        );
    }

    let show_progress = !cli.quiet && !cli.no_progress && !cli.json;
    let reporter = setup_reporter(show_progress, source_size);
    let throttled = ThrottledReporter::new(reporter.as_ref());

    let result = if mode == "encrypt" {
        crypto::encrypt_file(
            &input_path,
            &output_path,
            cli.force,
            password,
            &throttled,
            None,
        )
    } else {
        crypto::decrypt_file(
            &input_path,
            &output_path,
            cli.force,
            password,
            &throttled,
            None,
        )
    };

    match result {
        Ok(dest) => {
            let elapsed = start.elapsed().as_millis();
            if mode == "encrypt" {
                let hash = compute_sha256(&input_path).ok();
                emit_success_json(cli.json, &start, Some(dest.display().to_string()), source_size, hash.clone());
                if !cli.quiet && !cli.json {
                    eprintln!(
                        "✓ Written to {} ({:.2}s)",
                        dest.display(),
                        elapsed as f64 / 1000.0
                    );
                    if let Some(h) = &hash {
                        eprintln!("SHA-256 (original): {h}");
                    }
                }
            } else {
                let hash = compute_sha256(&dest).ok();
                emit_success_json(cli.json, &start, Some(dest.display().to_string()), source_size, hash.clone());
                if !cli.quiet && !cli.json {
                    eprintln!(
                        "✓ Written to {} ({:.2}s)",
                        dest.display(),
                        elapsed as f64 / 1000.0
                    );
                    if let Some(h) = &hash {
                        eprintln!("SHA-256 (decrypted): {h}");
                    }
                }
            }
            Ok(())
        }
        Err(CryptoError::DecryptionFailed) => {
            let msg = "Wrong passphrase or corrupted file.";
            emit_error_json(cli.json, &start, Some(output_path.display().to_string()), msg);
            if !cli.json {
                eprintln!("✗ {msg}");
            }
            Err(ExitCode::WrongPassword)
        }
        Err(e) => {
            let msg = e.to_string();
            emit_error_json(cli.json, &start, Some(output_path.display().to_string()), &msg);
            if !cli.json {
                eprintln!("✗ {msg}");
            }
            Err(ExitCode::RuntimeError)
        }
    }
}

fn run_stream(
    cli: &Cli,
    start: Instant,
    password: &[u8],
    mode: &str,
    input_str: &str,
    output_str: &Option<String>,
    is_pipe_in: bool,
    is_pipe_out: bool,
) -> Result<(), ExitCode> {
    let source_size = if !is_pipe_in {
        let p = PathBuf::from(input_str);
        fs::metadata(&p).ok().map(|m| m.len())
    } else {
        None
    };

    if !cli.quiet && !cli.json {
        let action = if mode == "encrypt" { "Encrypting" } else { "Decrypting" };
        eprintln!(
            "{} stdin → stdout{}",
            action,
            if let Some(s) = source_size {
                format!(" ({})", HumanBytes(s))
            } else {
                String::new()
            }
        );
    }

    let show_progress = !cli.quiet && !cli.no_progress && !cli.json && !is_pipe_out;
    let reporter = setup_reporter(show_progress, source_size);
    let throttled = ThrottledReporter::new(reporter.as_ref());

    let success_output_path: Option<String> = if is_pipe_out {
        Some("-".into())
    } else {
        output_str.clone()
    };

    let result = if mode == "encrypt" {
        if is_pipe_in {
            let msg = "Encryption from stdin is not supported (requires seeking). Use a file input instead.";
            emit_error_json(cli.json, &start, None, msg);
            eprintln!("Error: {msg}");
            return Err(ExitCode::BadInput);
        } else {
            let mut f = match fs::File::open(input_str) {
                Ok(f) => f,
                Err(e) => {
                    let msg = format!("Cannot open input: {e}");
                    emit_error_json(cli.json, &start, None, &msg);
                    eprintln!("Error: {msg}");
                    return Err(ExitCode::BadInput);
                }
            };
            let stdout = io::stdout();
            let mut stdout_lock = stdout.lock();
            crypto::encrypt_stream(
                &mut f,
                &mut stdout_lock,
                password,
                source_size,
                &throttled,
            )
        }
    } else {
        let mut reader: Box<dyn ReadSeek> = if is_pipe_in {
            let mut tmp = tempfile::tempfile().map_err(|e| {
                let msg = format!("Cannot create temporary file: {e}");
                emit_error_json(cli.json, &start, None, &msg);
                eprintln!("Error: {msg}");
                ExitCode::RuntimeError
            })?;
            io::copy(&mut io::stdin().lock(), &mut tmp).map_err(|e| {
                let msg = format!("Cannot read stdin: {e}");
                emit_error_json(cli.json, &start, None, &msg);
                eprintln!("Error: {msg}");
                ExitCode::RuntimeError
            })?;
            tmp.seek(io::SeekFrom::Start(0)).map_err(|e| {
                let msg = format!("Cannot seek temporary file: {e}");
                emit_error_json(cli.json, &start, None, &msg);
                eprintln!("Error: {msg}");
                ExitCode::RuntimeError
            })?;
            Box::new(tmp)
        } else {
            match fs::File::open(input_str) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    let msg = format!("Cannot open input: {e}");
                    emit_error_json(cli.json, &start, None, &msg);
                    eprintln!("Error: {msg}");
                    return Err(ExitCode::BadInput);
                }
            }
        };
        if is_pipe_out {
            let stdout = io::stdout();
            let mut stdout_lock = stdout.lock();
            crypto::decrypt_stream(
                &mut reader,
                &mut stdout_lock,
                password,
                source_size,
                &throttled,
            )
        } else if let Some(path) = output_str.as_deref() {
            let mut out = match fs::File::create(path) {
                Ok(f) => f,
                Err(e) => {
                    let msg = format!("Cannot open output: {e}");
                    emit_error_json(cli.json, &start, Some(path.to_owned()), &msg);
                    eprintln!("Error: {msg}");
                    return Err(ExitCode::BadInput);
                }
            };
            crypto::decrypt_stream(
                &mut reader,
                &mut out,
                password,
                source_size,
                &throttled,
            )
        } else {
            let msg = "Output path is required when decrypting piped input unless -o - is set.";
            emit_error_json(cli.json, &start, None, msg);
            eprintln!("Error: {msg}");
            return Err(ExitCode::BadInput);
        }
    };

    match result {
        Ok(()) => {
            let elapsed = start.elapsed().as_millis();
            emit_success_json(cli.json, &start, success_output_path, source_size, None);
            if !cli.quiet && !cli.json {
                eprintln!("✓ Complete ({:.2}s)", elapsed as f64 / 1000.0);
            }
            Ok(())
        }
        Err(CryptoError::DecryptionFailed) => {
            let msg = "Wrong passphrase or corrupted file.";
            emit_error_json(cli.json, &start, None, msg);
            if !cli.json {
                eprintln!("✗ {msg}");
            }
            Err(ExitCode::WrongPassword)
        }
        Err(e) => {
            let msg = e.to_string();
            emit_error_json(cli.json, &start, None, &msg);
            if !cli.json {
                eprintln!("✗ {msg}");
            }
            Err(ExitCode::RuntimeError)
        }
    }
}

fn run() -> Result<(), ExitCode> {
    let cli = Cli::parse();

    if let Some(shell) = &cli.completions {
        let mut cmd = Cli::command();
        generate(*shell, &mut cmd, "neuron-encrypt-cli", &mut io::stdout());
        return Ok(());
    }

    let start = Instant::now();
    let (input_str, output_str, mode) = match &cli.command {
        Command::Encrypt { input, output, .. } => (input.clone(), output.clone(), "encrypt"),
        Command::Decrypt { input, output } => (input.clone(), output.clone(), "decrypt"),
    };
    let password = match &cli.command {
        Command::Encrypt { no_confirm, .. }
            if std::env::var("NEURON_PASSWORD").is_err() && !no_confirm =>
        {
            match read_password_confirmed(&cli.password_file) {
                Ok(password) => password,
                Err((code, msg)) => {
                    emit_error_json(cli.json, &start, None, &msg);
                    eprintln!("Error: {msg}");
                    return Err(code);
                }
            }
        }
        _ => match read_password(&cli.password_file) {
            Ok(password) => password,
            Err((code, msg)) => {
                emit_error_json(cli.json, &start, None, &msg);
                eprintln!("Error: {msg}");
                return Err(code);
            }
        },
    };

    if password.len() < crypto::MIN_PASSWORD_LEN {
        let msg = format!(
            "Passphrase too short (minimum {} bytes).",
            crypto::MIN_PASSWORD_LEN
        );
        emit_error_json(cli.json, &start, None, &msg);
        eprintln!("Error: {msg}");
        return Err(ExitCode::BadInput);
    }

    let is_pipe_in = input_str == "-";
    let is_pipe_out = output_str.as_deref() == Some("-");

    if !is_pipe_in && !is_pipe_out {
        run_file(&cli, start, password.as_slice(), mode, &input_str, &output_str)
    } else {
        run_stream(&cli, start, password.as_slice(), mode, &input_str, &output_str, is_pipe_in, is_pipe_out)
    }
}

fn main() {
    match run() {
        Ok(()) => std::process::exit(ExitCode::Success as i32),
        Err(code) => std::process::exit(code as i32),
    }
}
