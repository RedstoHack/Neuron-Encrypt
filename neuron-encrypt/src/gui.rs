use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crossbeam_channel as mpsc;
use eframe::egui::{
    self, vec2, Align2, Color32, FontFamily, FontId, Pos2, Rect, Sense, Shape, Stroke,
    ViewportCommand,
};
use neuron_encrypt_core::crypto::{self, ProgressReporter, ThrottledReporter};
use neuron_encrypt_core::error::CryptoError;
use neuron_encrypt_core::utils::{constant_time_eq, format_size, is_vx2_file};
// P2-UI: rand_core import removed — was only used for scramble_text generation,
// which is deleted. The crypto module has its own OsRng import.
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn compute_sha256(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new([0u8; 65536]);
    loop {
        let n = file.read(&mut *buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

struct Palette;
impl Palette {
    const BG: Color32 = Color32::from_rgb(0x08, 0x08, 0x08);
    const SURFACE: Color32 = Color32::from_rgb(0x10, 0x10, 0x10);
    const SURFACE_HI: Color32 = Color32::from_rgb(0x1A, 0x1A, 0x1A);
    const BORDER: Color32 = Color32::from_rgb(0x28, 0x28, 0x28);
    const BORDER_FOCUS: Color32 = Color32::from_rgb(0x63, 0x66, 0xF1);
    const ACCENT: Color32 = Color32::from_rgb(0x63, 0x66, 0xF1);
    fn accent_dim() -> Color32 {
        Color32::from_rgba_unmultiplied(99, 102, 241, 18)
    }
    const TEXT_HI: Color32 = Color32::from_rgb(0xF5, 0xF5, 0xF5);
    const TEXT_MED: Color32 = Color32::from_rgb(0x9A, 0x9A, 0x9A);
    const TEXT_LO: Color32 = Color32::from_rgb(0x4A, 0x4A, 0x4A);
    const SUCCESS: Color32 = Color32::from_rgb(0x10, 0xB9, 0x81);
    const ERROR: Color32 = Color32::from_rgb(0xF4, 0x3F, 0x5E);
    const WARNING: Color32 = Color32::from_rgb(0xF5, 0x9E, 0x0B);

    const SURFACE_1: Color32 = Color32::from_rgb(0x16, 0x16, 0x16);
    const SURFACE_2: Color32 = Color32::from_rgb(0x1E, 0x1E, 0x1E);
    const BORDER_SUBTLE: Color32 = Color32::from_rgb(0x1A, 0x1A, 0x1A);
    const BORDER_MED: Color32 = Color32::from_rgb(0x2A, 0x2A, 0x2A);
    const ACCENT_HOVER: Color32 = Color32::from_rgb(0x81, 0x8C, 0xF8);
    fn accent_muted() -> Color32 {
        Color32::from_rgba_unmultiplied(99, 102, 241, 30)
    }
    fn success_muted() -> Color32 {
        Color32::from_rgba_unmultiplied(16, 185, 129, 30)
    }
    fn error_muted() -> Color32 {
        Color32::from_rgba_unmultiplied(244, 63, 94, 30)
    }
    fn warning_muted() -> Color32 {
        Color32::from_rgba_unmultiplied(245, 158, 11, 30)
    }
    const TEXT_ACCENT: Color32 = Color32::from_rgb(0x81, 0x8C, 0xF8);
}

#[derive(PartialEq, Clone, Copy)]
enum AppFlow {
    FileDrop,
    Configure,
    Processing,
    Success,
    Failure,
    BatchConfigure,
    BatchProcessing,
    BatchDone,
}

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(PartialEq, Clone, Copy)]
enum Strength {
    None,
    Weak,
    Fair,
    Strong,
    Elite,
}

enum GuiMsg {
    Progress(f32, String),
    Done(String, Option<String>),
    Error(CryptoError),
    // Batch messages
    BatchFileProgress(usize, f32, String), // (file_index, progress, message)
    BatchFileDone(usize, PathBuf, Option<String>), // (file_index, dest_path, sha256)
    BatchFileError(usize, String),         // (file_index, error_message)
    BatchAllDone,
}

#[derive(Clone)]
struct BatchResult {
    src_name: String,
    dest_path: Option<PathBuf>,
    sha256: Option<String>,
    error: Option<String>,
}

enum ButtonKind {
    Primary,
    Secondary,
}

struct MpscReporter {
    tx: mpsc::Sender<GuiMsg>,
}

impl ProgressReporter for MpscReporter {
    fn report(&self, progress: f32, message: &str) {
        let _ = self
            .tx
            .try_send(GuiMsg::Progress(progress, message.to_owned()));
    }
}

pub struct NeuronEncryptApp {
    mode: Mode,
    flow: AppFlow,
    selected_file: Option<PathBuf>,
    dest_path: Option<PathBuf>,
    sha256_hash: Option<String>,
    // Batch
    batch_files: Vec<PathBuf>,
    batch_results: Vec<BatchResult>,
    batch_current_index: usize,
    batch_current_file_progress: f32,
    password: Zeroizing<String>,
    confirm_password: Zeroizing<String>,
    show_password: bool,
    crypto_rx: Option<mpsc::Receiver<GuiMsg>>,
    progress: f32,
    status: Option<String>,
    spinner_index: usize,
    last_spinner_tick: Instant,
    // P2-UI: scramble_text field removed — ACTIVITY panel was deleted.
    reencrypt_confirmed: bool,
    strength_frac: f32,
    prog_frac: f32,
    check_anim: f32,
    cancel_flag: Arc<AtomicBool>,
}

fn truncate_chars(s: &str, n: usize) -> String {
    let mut out = s.chars().take(n).collect::<String>();
    if s.chars().count() > n {
        out.push_str("...");
    }
    out
}

fn sanitize_text(s: &str) -> String {
    s.trim().to_owned()
}

fn strength_color(strength: Strength) -> Color32 {
    match strength {
        Strength::None => Palette::BORDER,
        Strength::Weak => Palette::ERROR,
        Strength::Fair => Palette::WARNING,
        Strength::Strong => Palette::ACCENT,
        Strength::Elite => Palette::SUCCESS,
    }
}

fn eval_strength(password: &str) -> (Strength, f32, &'static str) {
    if password.is_empty() {
        return (Strength::None, 0.0, "None");
    }

    let len = password.chars().count();
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    // Charset size
    let mut charset_size: f64 = 0.0;
    if has_lower {
        charset_size += 26.0;
    }
    if has_upper {
        charset_size += 26.0;
    }
    if has_digit {
        charset_size += 10.0;
    }
    if has_symbol {
        charset_size += 33.0;
    }
    if charset_size == 0.0 {
        charset_size = 1.0;
    }

    // Base entropy: len * log2(charset_size)
    let mut entropy = (len as f64) * (charset_size.log2());

    // Pattern penalties
    entropy -= repeated_chars_penalty(password);
    entropy -= sequence_penalty(password);
    entropy -= common_password_penalty(password);

    // Length bonus (passphrases are strong even with small charset)
    if len >= 20 {
        entropy += 10.0;
    }
    if len >= 32 {
        entropy += 15.0;
    }

    let entropy = entropy.max(0.0);
    let fraction = ((entropy / 80.0) as f32).clamp(0.0, 1.0);

    // Map entropy to strength tiers (NIST 800-63B guidance)
    if entropy < 28.0 {
        (Strength::Weak, fraction, "Weak")
    } else if entropy < 36.0 {
        (Strength::Fair, fraction, "Fair")
    } else if entropy < 60.0 {
        (Strength::Strong, fraction, "Strong")
    } else {
        (Strength::Elite, fraction, "Elite")
    }
}

/// Penalize repeated characters (aaa, 111, !!!).
fn repeated_chars_penalty(password: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    let mut penalty = 0.0f64;
    let mut run_len = 1usize;
    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run_len += 1;
        } else {
            if run_len >= 3 {
                penalty += ((run_len - 2) as f64) * 3.0;
            }
            run_len = 1;
        }
    }
    if run_len >= 3 {
        penalty += ((run_len - 2) as f64) * 3.0;
    }
    penalty
}

/// Penalize keyboard/alphabetical sequences (abc, 123, qwerty).
fn sequence_penalty(password: &str) -> f64 {
    let lower = password.to_lowercase();
    let sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "0123456789",
        "!@#$%^&*",
    ];

    let mut penalty = 0.0f64;
    for seq in &sequences {
        // Forward sequences of length >= 3
        if seq.len() >= 3 {
            for i in 0..=seq.len().saturating_sub(3) {
                let sub = &seq[i..i + 3];
                if lower.contains(sub) {
                    penalty += 5.0;
                }
            }
        }
        // Reversed sequences
        let reversed: String = seq.chars().rev().collect();
        if reversed.len() >= 3 {
            for i in 0..=reversed.len().saturating_sub(3) {
                let sub = &reversed[i..i + 3];
                if lower.contains(sub) {
                    penalty += 5.0;
                }
            }
        }
    }
    penalty
}

/// Penalize common passwords (subset of top 100).
fn common_password_penalty(password: &str) -> f64 {
    let lower = password.to_lowercase();
    let common = [
        "password", "pass", "123456", "12345678", "qwerty", "abc123", "monkey",
        "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
        "master", "sunshine", "ashley", "michael", "shadow", "123123", "654321",
        "superman", "qazwsx", "football", "password1", "password123", "admin",
        "welcome", "hello", "freedom", "whatever", "hunter2", "password!",
        "p@ssw0rd", "p@ssword",
    ];

    for cp in &common {
        if lower == *cp || lower.starts_with(cp) {
            return 40.0;
        }
    }
    0.0
}

fn preview_output_name(mode: Mode, path: &Path) -> String {
    match mode {
        Mode::Encrypt => crypto::default_encrypt_output_name(path),
        Mode::Decrypt => crypto::default_decrypt_output_name(path),
    }
}

impl NeuronEncryptApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            mode: Mode::Encrypt,
            flow: AppFlow::FileDrop,
            selected_file: None,
            dest_path: None,
            sha256_hash: None,
            batch_files: Vec::new(),
            batch_results: Vec::new(),
            batch_current_index: 0,
            batch_current_file_progress: 0.0,
            password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            show_password: false,
            crypto_rx: None,
            progress: 0.0,
            status: None,
            spinner_index: 0,
            last_spinner_tick: Instant::now(),
            reencrypt_confirmed: false,
            strength_frac: 0.0,
            prog_frac: 0.0,
            check_anim: 0.0,
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    fn secure_wipe_session(&mut self, ctx: &egui::Context) {
        self.mode = Mode::Encrypt;
        self.password = Zeroizing::new(String::new());
        self.confirm_password = Zeroizing::new(String::new());
        self.selected_file = None;
        self.dest_path = None;
        self.sha256_hash = None;
        self.batch_files.clear();
        self.batch_results.clear();
        self.batch_current_index = 0;
        self.batch_current_file_progress = 0.0;
        self.crypto_rx = None;
        self.status = None;
        self.show_password = false;
        self.flow = AppFlow::FileDrop;
        self.progress = 0.0;
        self.prog_frac = 0.0;
        self.reencrypt_confirmed = false;
        self.strength_frac = 0.0;
        self.check_anim = 0.0;
        self.cancel_flag.store(false, Ordering::SeqCst);

        // Clear all GUI state and focus to drop transient internal buffers
        ctx.memory_mut(|mem| {
            // In egui 0.28, surrender_focus takes an Id.
            // Using Id::NULL forces any currently focused widget to lose focus.
            mem.surrender_focus(egui::Id::NULL);
        });
    }

    fn set_selected_file(&mut self, path: PathBuf) {
        self.mode = if is_vx2_file(&path) {
            Mode::Decrypt
        } else {
            Mode::Encrypt
        };
        self.selected_file = Some(path);
        self.dest_path = None;
        self.flow = AppFlow::Configure;
        self.password = Zeroizing::new(String::new());
        self.confirm_password = Zeroizing::new(String::new());
        self.show_password = false;
        self.status = None;
        self.progress = 0.0;
        self.prog_frac = 0.0;
        self.reencrypt_confirmed = false;
        self.cancel_flag.store(false, Ordering::SeqCst);
    }

    fn pick_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.set_selected_file(path);
        }
    }

    fn screen_badge(&self) -> (&'static str, Color32, Color32) {
        match self.flow {
            AppFlow::FileDrop => ("LOCAL ONLY", Palette::accent_muted(), Palette::TEXT_ACCENT),
            AppFlow::Configure => match self.mode {
                Mode::Encrypt => ("ENCRYPT", Palette::accent_muted(), Palette::TEXT_ACCENT),
                Mode::Decrypt => ("DECRYPT", Palette::accent_muted(), Palette::TEXT_ACCENT),
            },
            AppFlow::Processing => ("PROCESSING", Palette::accent_muted(), Palette::TEXT_ACCENT),
            AppFlow::Success => ("COMPLETE", Palette::success_muted(), Palette::SUCCESS),
            AppFlow::Failure => ("ERROR", Palette::error_muted(), Palette::ERROR),
            AppFlow::BatchConfigure => ("BATCH", Palette::accent_muted(), Palette::TEXT_ACCENT),
            AppFlow::BatchProcessing => (
                "BATCH · PROCESSING",
                Palette::accent_muted(),
                Palette::TEXT_ACCENT,
            ),
            AppFlow::BatchDone => ("BATCH · DONE", Palette::success_muted(), Palette::SUCCESS),
        }
    }

    fn screen_title(&self) -> &'static str {
        match self.flow {
            AppFlow::FileDrop => "Protect a file on this device",
            AppFlow::Configure => match self.mode {
                Mode::Encrypt => "Review the file and encrypt it",
                Mode::Decrypt => "Review the file and decrypt it",
            },
            AppFlow::Processing => "Working on your file",
            AppFlow::Success => match self.mode {
                Mode::Encrypt => "Encryption complete",
                Mode::Decrypt => "Decryption complete",
            },
            AppFlow::Failure => "The operation did not finish",
            AppFlow::BatchConfigure => "Set up batch operation",
            AppFlow::BatchProcessing => "Processing your files",
            AppFlow::BatchDone => "Batch operation complete",
        }
    }

    fn screen_subtitle(&self) -> &'static str {
        match self.flow {
            AppFlow::FileDrop => {
                "Drag a file here or browse from disk. Everything stays local to this machine."
            }
            AppFlow::Configure => {
                "Choose the mode, enter a passphrase, and save the output as a new file."
            }
            AppFlow::Processing => {
                "The current run is happening locally. Keep this window open until it finishes."
            }
            AppFlow::Success => {
                "Your output file is ready. You can open its folder or start another run."
            }
            AppFlow::Failure => "Review the message below, then return to the start and try again.",
            AppFlow::BatchConfigure => {
                "All files use the same passphrase. Output is saved beside each source file."
            }
            AppFlow::BatchProcessing => {
                "Files are being processed one by one. Keep this window open until finished."
            }
            AppFlow::BatchDone => {
                "Review per-file results below. Outputs are saved beside each original."
            }
        }
    }

    fn execute(&mut self, ctx: &egui::Context) {
        let Some(file_path) = self.selected_file.clone() else {
            return;
        };

        if self.password.chars().count() < crypto::MIN_PASSWORD_LEN {
            self.status = Some(format!(
                "Passphrase must be at least {} characters.",
                crypto::MIN_PASSWORD_LEN
            ));
            return;
        }

        if self.mode == Mode::Encrypt
            && !constant_time_eq(self.password.as_bytes(), self.confirm_password.as_bytes())
        {
            self.status = Some("Passphrases do not match.".to_owned());
            return;
        }

        if self.mode == Mode::Encrypt && is_vx2_file(&file_path) && !self.reencrypt_confirmed {
            self.status = Some("Re-encrypt acknowledgement required.".to_owned());
            return;
        }

        // Decrypt: save automatically beside source. Encrypt: ask user where.
        let dest = if self.mode == Mode::Decrypt {
            let dst_name = preview_output_name(self.mode, &file_path);
            match file_path.parent() {
                Some(parent) => parent.join(&dst_name),
                None => PathBuf::from(&dst_name),
            }
        } else {
            let dst_name = preview_output_name(self.mode, &file_path);
            let Some(dest) = rfd::FileDialog::new()
                .set_directory(file_path.parent().unwrap_or(Path::new(".")))
                .set_file_name(&dst_name)
                .save_file()
            else {
                return;
            };
            dest
        };

        self.dest_path = Some(dest.clone());
        self.progress = 0.0;
        self.prog_frac = 0.0;
        self.status = Some("Preparing secure file operation...".to_owned());
        self.cancel_flag.store(false, Ordering::SeqCst);

        let (tx, rx) = mpsc::unbounded();
        self.crypto_rx = Some(rx);
        self.flow = AppFlow::Processing;

        let password = self.password.clone();
        let mode = self.mode;
        let ctx_clone = ctx.clone();
        // P1-2: clone the cancel_flag Arc so the spawned thread can poll it.
        let cancel_for_thread = self.cancel_flag.clone();
        self.password = Zeroizing::new(String::new());
        self.confirm_password = Zeroizing::new(String::new());
        self.show_password = false;

        std::thread::spawn(move || {
            let reporter = MpscReporter { tx: tx.clone() };
            let throttled_reporter = ThrottledReporter::new(&reporter);

            let result = if mode == Mode::Encrypt {
                crypto::encrypt_file(
                    &file_path,
                    &dest,
                    false,
                    password.as_bytes(),
                    &throttled_reporter,
                    Some(&cancel_for_thread),
                )
            } else {
                crypto::decrypt_file(
                    &file_path,
                    &dest,
                    false,
                    password.as_bytes(),
                    &throttled_reporter,
                    Some(&cancel_for_thread),
                )
            };

            match result {
                Ok(_) => {
                    // P2-4: always hash the OUTPUT file (ciphertext on encrypt, plaintext on decrypt).
                    // Avoids leaking a plaintext-hash verifier via screenshots.
                    let hash = compute_sha256(&dest);
                    let _ = tx.try_send(GuiMsg::Done("Operation complete.".to_owned(), hash));
                }
                Err(CryptoError::Cancelled) => {
                    // P1-2: user pressed Cancel. Report as Done (not Error) with a
                    // clear message so the user doesn't see a scary "Error" screen.
                    let _ = tx.try_send(GuiMsg::Done(
                        "Operation cancelled by user. No output file was written.".to_owned(),
                        None,
                    ));
                }
                Err(e) => {
                    let _ = tx.try_send(GuiMsg::Error(e));
                }
            }

            ctx_clone.request_repaint();
        });
    }

    /// Launch batch processing for all files in `self.batch_files`.
    /// Files are processed sequentially in a background thread.
    /// Each file's output is saved beside the source with the appropriate extension.
    fn execute_batch(&mut self, ctx: &egui::Context) {
        if self.batch_files.is_empty() {
            return;
        }
        if self.password.chars().count() < crypto::MIN_PASSWORD_LEN {
            self.status = Some(format!(
                "Passphrase must be at least {} characters.",
                crypto::MIN_PASSWORD_LEN
            ));
            return;
        }
        if self.mode == Mode::Encrypt
            && !constant_time_eq(self.password.as_bytes(), self.confirm_password.as_bytes())
        {
            self.status = Some("Passphrases do not match.".to_owned());
            return;
        }

        // Build initial BatchResult placeholders
        self.batch_results = self
            .batch_files
            .iter()
            .map(|p| BatchResult {
                src_name: p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| String::from("(unknown)")),
                dest_path: None,
                sha256: None,
                error: None,
            })
            .collect();

        self.batch_current_index = 0;
        self.batch_current_file_progress = 0.0;
        self.progress = 0.0;
        self.prog_frac = 0.0;
        self.cancel_flag.store(false, Ordering::SeqCst);

        let (tx, rx) = mpsc::unbounded();
        self.crypto_rx = Some(rx);
        self.flow = AppFlow::BatchProcessing;

        let password = self.password.clone();
        let mode = self.mode;
        let files = self.batch_files.clone();
        let ctx_clone = ctx.clone();
        let cancel = self.cancel_flag.clone();
        self.password = Zeroizing::new(String::new());
        self.confirm_password = Zeroizing::new(String::new());
        self.show_password = false;

        std::thread::spawn(move || {
            let total = files.len();

            for (idx, src) in files.iter().enumerate() {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }

                let dest_name = preview_output_name(mode, src);
                let dest = match src.parent() {
                    Some(parent) => parent.join(&dest_name),
                    None => std::path::PathBuf::from(&dest_name),
                };

                // Per-file progress reporter that maps 0..1 → slice of overall progress
                let tx_clone = tx.clone();
                let idx_copy = idx;
                let total_copy = total;
                let file_reporter = move |frac: f32, msg: &str| {
                    let _ = tx_clone.try_send(GuiMsg::BatchFileProgress(
                        idx_copy,
                        frac,
                        msg.to_owned(),
                    ));
                    let _ = tx_clone.try_send(GuiMsg::Progress(
                        (idx_copy as f32 + frac) / total_copy as f32,
                        msg.to_owned(),
                    ));
                };

                struct FnReporter<F: Fn(f32, &str) + Send + Sync>(F);
                impl<F: Fn(f32, &str) + Send + Sync> ProgressReporter for FnReporter<F> {
                    fn report(&self, p: f32, m: &str) {
                        (self.0)(p, m);
                    }
                }
                let reporter = FnReporter(file_reporter);
                let throttled = ThrottledReporter::new(&reporter);

                // P1-4: skip already-encrypted .vx2 files in batch encrypt mode to avoid
                // silent double-encryption producing .vx2.vx2 outputs.
                if mode == Mode::Encrypt && is_vx2_file(src) {
                    let _ = tx.try_send(GuiMsg::BatchFileError(
                        idx,
                        "Skipped: file already has .vx2 extension. Untick 'Encrypt' or remove the file.".to_string(),
                    ));
                    ctx_clone.request_repaint();
                    continue;
                }

                let result = if mode == Mode::Encrypt {
                    crypto::encrypt_file(
                        src,
                        &dest,
                        false,
                        password.as_bytes(),
                        &throttled,
                        Some(&cancel),
                    )
                } else {
                    crypto::decrypt_file(
                        src,
                        &dest,
                        false,
                        password.as_bytes(),
                        &throttled,
                        Some(&cancel),
                    )
                };

                match result {
                    Ok(out_path) => {
                        // C2-1 fix: always hash the OUTPUT file (ciphertext on encrypt,
                        // plaintext on decrypt). Previously batch mode hashed the source
                        // on encrypt — a screenshot-leak verifier for the plaintext.
                        let hash = compute_sha256(&out_path);
                        let _ = tx.try_send(GuiMsg::BatchFileDone(idx, out_path, hash));
                    }
                    Err(CryptoError::Cancelled) => {
                        // P1-2: mid-file cancel in batch — mark this file as cancelled
                        // and stop processing remaining files.
                        let _ = tx.try_send(GuiMsg::BatchFileError(idx, "Cancelled".to_string()));
                        break;
                    }
                    Err(e) => {
                        let _ = tx.try_send(GuiMsg::BatchFileError(idx, e.to_string()));
                    }
                }

                ctx_clone.request_repaint();
            }

            let _ = tx.try_send(GuiMsg::BatchAllDone);
            ctx_clone.request_repaint();
        });
    }

    fn pick_multiple_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            let all_vx2 = paths.iter().all(|p| is_vx2_file(p));
            let none_vx2 = paths.iter().all(|p| !is_vx2_file(p));
            self.mode = if all_vx2 {
                Mode::Decrypt
            } else if none_vx2 {
                Mode::Encrypt
            } else {
                // Mixed — default to encrypt; user can change
                Mode::Encrypt
            };
            self.batch_files = paths;
            self.batch_results.clear();
            self.password = Zeroizing::new(String::new());
            self.confirm_password = Zeroizing::new(String::new());
            self.status = None;
            self.flow = AppFlow::BatchConfigure;
        }
    }

    fn draw_title_bar(&mut self, ui: &mut egui::Ui) {
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 44.0), Sense::hover());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 0.0, Palette::BG);
        painter.line_segment(
            [
                Pos2::new(rect.min.x, rect.max.y - 1.0),
                Pos2::new(rect.max.x, rect.max.y - 1.0),
            ],
            Stroke::new(1.0_f32, Palette::BORDER),
        );

        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(rect.min.x + 16.0, rect.min.y + 12.0),
                Pos2::new(rect.min.x + 24.0, rect.min.y + 20.0),
            ),
            4.0,
            Palette::ACCENT,
        );
        let dot_rect = Rect::from_min_max(
            Pos2::new(rect.min.x + 14.0, rect.min.y + 10.0),
            Pos2::new(rect.min.x + 26.0, rect.min.y + 22.0),
        );
        let dot_response = ui.interact(dot_rect, ui.id().with("dot_drag"), Sense::drag());
        if dot_response.dragged() {
            ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
        }
        painter.text(
            Pos2::new(rect.min.x + 32.0, rect.min.y + 9.0),
            Align2::LEFT_TOP,
            "NEURON ENCRYPT",
            FontId::new(13.0, FontFamily::Monospace),
            Palette::TEXT_HI,
        );
        painter.text(
            Pos2::new(rect.min.x + 32.0, rect.min.y + 25.0),
            Align2::LEFT_TOP,
            "Secure local file encryption",
            FontId::new(10.0, FontFamily::Monospace),
            Palette::TEXT_LO,
        );

        let drag_rect = Rect::from_min_max(
            Pos2::new(rect.min.x, rect.min.y),
            Pos2::new(rect.max.x - 126.0, rect.max.y),
        );
        let drag_response = ui.interact(drag_rect, ui.id().with("drag"), Sense::click_and_drag());
        if drag_response.dragged() {
            ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
        }

        let mut x = rect.max.x - 12.0;
        for (kind, label, width) in [("close", "X", 30.0), ("min", "-", 30.0)] {
            let button_rect = Rect::from_min_max(
                Pos2::new(x - width, rect.center().y - 12.0),
                Pos2::new(x, rect.center().y + 12.0),
            );
            let response = ui.interact(button_rect, ui.id().with(kind), Sense::click());

            let (fill, stroke_color, text_color) = match kind {
                "close" if response.hovered() => {
                    (Palette::error_muted(), Palette::ERROR, Palette::ERROR)
                }
                "min" if response.hovered() => {
                    (Palette::warning_muted(), Palette::WARNING, Palette::WARNING)
                }
                _ => (Palette::SURFACE_1, Palette::BORDER, Palette::TEXT_MED),
            };

            painter.rect_filled(button_rect, 7.0, fill);
            painter.rect_stroke(
                button_rect,
                7.0,
                Stroke::new(1.0_f32, stroke_color),
                egui::StrokeKind::Outside,
            );
            painter.text(
                button_rect.center(),
                Align2::CENTER_CENTER,
                label,
                FontId::new(10.5, FontFamily::Monospace),
                text_color,
            );

            if response.clicked() {
                match kind {
                    "close" => ui.ctx().send_viewport_cmd(ViewportCommand::Close),
                    "min" => ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true)),
                    _ => {}
                }
            }

            x -= width + 8.0;
        }
    }

    fn draw_screen_header(&self, ui: &mut egui::Ui) {
        let rounding = 12.0; // Perfect pill shape for approx 24px height
        let (badge, fill, text_color) = self.screen_badge();
        egui::Frame::new()
            .fill(fill)
            .stroke(Stroke::new(1.0_f32, Palette::BORDER_MED))
            .corner_radius(rounding)
            .inner_margin(6.0)
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(badge)
                        .font(FontId::new(10.5, FontFamily::Monospace))
                        .color(text_color),
                );
            });

        ui.add_space(14.0);
        ui.label(
            egui::RichText::new(self.screen_title())
                .font(FontId::new(24.0, FontFamily::Monospace))
                .color(Palette::TEXT_HI)
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(self.screen_subtitle())
                .font(FontId::new(11.5, FontFamily::Monospace))
                .color(Palette::TEXT_MED),
        );
    }

    fn draw_button(
        &self,
        ui: &mut egui::Ui,
        label: &str,
        size: egui::Vec2,
        kind: ButtonKind,
        enabled: bool,
    ) -> egui::Response {
        let sense = if enabled {
            Sense::click()
        } else {
            Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(size, sense);
        let painter = ui.painter_at(rect);

        let (fill, stroke_color, text_color) = match kind {
            ButtonKind::Primary if !enabled => {
                (Palette::SURFACE_HI, Palette::BORDER, Palette::TEXT_LO)
            }
            ButtonKind::Primary if response.hovered() => (
                Palette::ACCENT_HOVER,
                Palette::ACCENT_HOVER,
                Palette::TEXT_HI,
            ),
            ButtonKind::Primary => (Palette::ACCENT, Palette::ACCENT, Palette::TEXT_HI),
            ButtonKind::Secondary if response.hovered() => {
                (Palette::SURFACE_2, Palette::BORDER_MED, Palette::TEXT_HI)
            }
            ButtonKind::Secondary => (Palette::SURFACE_1, Palette::BORDER, Palette::TEXT_MED),
        };

        painter.rect_filled(rect, 8.0, fill);
        painter.rect_stroke(
            rect,
            8.0,
            Stroke::new(1.0_f32, stroke_color),
            egui::StrokeKind::Outside,
        );
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            label,
            FontId::new(12.0, FontFamily::Monospace),
            text_color,
        );

        response
    }

    fn draw_file_drop(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);

        let dropped_files = ui.ctx().input(|i| i.raw.dropped_files.clone());
        if let Some(path) = dropped_files.first().and_then(|f| f.path.clone()) {
            self.set_selected_file(path);
        }
        let hover_drop = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 170.0), Sense::click());
        let painter = ui.painter_at(rect);

        painter.rect_filled(
            rect,
            12.0,
            if hover_drop {
                Palette::accent_dim()
            } else {
                Palette::SURFACE_1
            },
        );
        painter.rect_stroke(
            rect,
            12.0,
            Stroke::new(
                1.0_f32,
                if hover_drop {
                    Palette::ACCENT
                } else {
                    Palette::BORDER_MED
                },
            ),
            egui::StrokeKind::Outside,
        );
        painter.text(
            rect.center_top() + vec2(0.0, 42.0),
            Align2::CENTER_CENTER,
            if hover_drop {
                "Release to select this file"
            } else {
                "Drag a file here"
            },
            FontId::new(15.0, FontFamily::Monospace),
            Palette::TEXT_HI,
        );
        painter.text(
            rect.center_top() + vec2(0.0, 70.0),
            Align2::CENTER_CENTER,
            "Encrypt normal files and open .vx2 files for decryption.",
            FontId::new(11.0, FontFamily::Monospace),
            Palette::TEXT_MED,
        );
        painter.text(
            rect.center_top() + vec2(0.0, 100.0),
            Align2::CENTER_CENTER,
            "Click anywhere in this area to browse from disk.",
            FontId::new(10.5, FontFamily::Monospace),
            Palette::TEXT_LO,
        );

        if response.clicked() {
            self.pick_file();
        }

        ui.add_space(16.0);
        let button_width = (ui.available_width() - 8.0) * 0.5;
        ui.horizontal_centered(|ui| {
            if self
                .draw_button(
                    ui,
                    "Browse file",
                    vec2(button_width, 40.0),
                    ButtonKind::Secondary,
                    true,
                )
                .clicked()
            {
                self.pick_file();
            }
            if self
                .draw_button(
                    ui,
                    "Batch upload",
                    vec2(button_width, 40.0),
                    ButtonKind::Secondary,
                    true,
                )
                .clicked()
            {
                self.pick_multiple_files();
            }
        });
    }

    fn draw_file_summary(&mut self, ui: &mut egui::Ui) {
        let Some(path) = self.selected_file.clone() else {
            return;
        };

        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let location = path
            .parent()
            .map(|parent| truncate_chars(&parent.display().to_string(), 52))
            .unwrap_or_else(|| String::from("."));
        let size = std::fs::metadata(&path)
            .map(|meta| format_size(meta.len()))
            .unwrap_or_else(|_| String::from("Unknown size"));
        let output = preview_output_name(self.mode, &path);

        egui::Frame::new()
            .fill(Palette::SURFACE_1)
            .stroke(Stroke::new(1.0_f32, Palette::BORDER))
            .corner_radius(10.0)
            .inner_margin(14.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("SELECTED FILE")
                                .font(FontId::new(10.0, FontFamily::Monospace))
                                .color(Palette::TEXT_ACCENT),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(truncate_chars(&name, 42))
                                .font(FontId::new(14.0, FontFamily::Monospace))
                                .color(Palette::TEXT_HI),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(location)
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        if self
                            .draw_button(
                                ui,
                                "Change file",
                                vec2(110.0, 34.0),
                                ButtonKind::Secondary,
                                true,
                            )
                            .clicked()
                        {
                            self.pick_file();
                        }
                    });
                });

                ui.add_space(12.0);
                let (divider, _) =
                    ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
                ui.painter_at(divider).line_segment(
                    [divider.left_center(), divider.right_center()],
                    Stroke::new(1.0_f32, Palette::BORDER_SUBTLE),
                );
                ui.add_space(12.0);

                ui.label(
                    egui::RichText::new(format!("Size   {size}"))
                        .font(FontId::new(10.5, FontFamily::Monospace))
                        .color(Palette::TEXT_MED),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("Output {}", truncate_chars(&output, 44)))
                        .font(FontId::new(10.5, FontFamily::Monospace))
                        .color(Palette::TEXT_MED),
                );
            });
    }

    fn draw_password_row(&mut self, ui: &mut egui::Ui, label: &str, primary: bool) {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(label)
                    .font(FontId::new(11.5, FontFamily::Monospace))
                    .color(Palette::TEXT_MED),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self
                    .draw_button(
                        ui,
                        if self.show_password { "Hide" } else { "Show" },
                        vec2(64.0, 30.0),
                        ButtonKind::Secondary,
                        true,
                    )
                    .clicked()
                {
                    self.show_password = !self.show_password;
                }
            });
        });

        ui.add_space(6.0);

        let total_width = ui.available_width();
        let (rect, _) = ui.allocate_exact_size(vec2(total_width, 42.0), Sense::hover());
        let id = if primary {
            ui.id().with("pw")
        } else {
            ui.id().with("cpw")
        };
        let focus = ui.memory(|memory| memory.has_focus(id));
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 8.0, Palette::SURFACE_HI);
        painter.rect_stroke(
            rect,
            8.0,
            Stroke::new(
                1.0_f32,
                if focus {
                    Palette::BORDER_FOCUS
                } else {
                    Palette::BORDER
                },
            ),
            egui::StrokeKind::Outside,
        );

        let input_rect =
            Rect::from_min_max(rect.min + vec2(12.0, 11.0), rect.max - vec2(12.0, 11.0));
        ui.scope_builder(egui::UiBuilder::new().max_rect(input_rect), |ui| {
            let edit = if primary {
                egui::TextEdit::singleline(&mut *self.password).id(id)
            } else {
                egui::TextEdit::singleline(&mut *self.confirm_password).id(id)
            };
            // Disable history/undo for password fields to avoid memory caching
            ui.add(
                edit.frame(false)
                    .password(!self.show_password)
                    .char_limit(128)
                    .interactive(true),
            );
        });
    }

    fn draw_strength_meter(&self, ui: &mut egui::Ui, label: &str) {
        let strength = eval_strength(&self.password).0;

        // P2-UI: Single-line layout — "Strength: <word>" with a thin bar below.
        // Removed the multi-line breakdown and the misleading "Use at least N
        // characters" hint (NIST 800-63B Rev. 4 says composition rules are
        // misleading; the strength word is enough).
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Strength")
                    .font(FontId::new(11.0, FontFamily::Monospace))
                    .color(Palette::TEXT_MED),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(label)
                        .font(FontId::new(11.0, FontFamily::Monospace))
                        .color(strength_color(strength))
                        .strong(),
                );
            });
        });

        ui.add_space(6.0);
        let (bar_rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 4.0), Sense::hover());
        let painter = ui.painter_at(bar_rect);
        painter.rect_filled(bar_rect, 2.0, Palette::BORDER);
        let fill_rect = Rect::from_min_max(
            bar_rect.min,
            Pos2::new(
                bar_rect.min.x + bar_rect.width() * self.strength_frac,
                bar_rect.max.y,
            ),
        );
        painter.rect_filled(fill_rect, 2.0, strength_color(strength));
    }

    fn draw_notice(
        &self,
        ui: &mut egui::Ui,
        title: &str,
        body: &str,
        fill: Color32,
        border: Color32,
        text: Color32,
    ) {
        egui::Frame::new()
            .fill(fill)
            .stroke(Stroke::new(1.0_f32, border))
            .corner_radius(8.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(title)
                        .font(FontId::new(11.0, FontFamily::Monospace))
                        .color(text)
                        .strong(),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(body)
                        .font(FontId::new(10.5, FontFamily::Monospace))
                        .color(Palette::TEXT_MED),
                );
            });
    }

    fn draw_configure(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, strength_label: &str) {
        ui.horizontal(|ui| {
            if self
                .draw_button(ui, "< Back", vec2(92.0, 34.0), ButtonKind::Secondary, true)
                .clicked()
            {
                self.secure_wipe_session(ctx);
            }
        });

        ui.add_space(16.0);
        self.draw_file_summary(ui);

        // P2-UI: Contextual one-liner above the password field — educates the
        // user about what's happening without dumping crypto jargon (sii.pl
        // principle #2: educate in context).
        ui.add_space(14.0);
        let context_line = match self.mode {
            Mode::Encrypt => "Enter a passphrase to encrypt this file. You'll need it to decrypt later — there is no recovery.",
            Mode::Decrypt => "Enter the passphrase used to encrypt this file.",
        };
        ui.label(
            egui::RichText::new(context_line)
                .font(FontId::new(11.0, FontFamily::Monospace))
                .color(Palette::TEXT_MED),
        );

        ui.add_space(12.0);
        self.draw_password_row(ui, "Passphrase", true);

        if self.mode == Mode::Encrypt {
            ui.add_space(12.0);
            self.draw_password_row(ui, "Confirm passphrase", false);

            if !self.password.is_empty()
                && !self.confirm_password.is_empty()
                && !constant_time_eq(self.password.as_bytes(), self.confirm_password.as_bytes())
            {
                ui.add_space(8.0);
                self.draw_notice(
                    ui,
                    "Passphrases do not match",
                    "Enter the same passphrase in both fields before continuing.",
                    Palette::error_muted(),
                    Palette::ERROR,
                    Palette::ERROR,
                );
            }
        }

        ui.add_space(14.0);
        self.draw_strength_meter(ui, strength_label);

        // P2-UI: Hide cipher/KDF details behind an "Advanced" CollapsingHeader.
        // Per UI research §7.5, non-experts don't need to see "AES-256-GCM-SIV
        // BE32" — defaults are correct, surface them only when asked.
        ui.add_space(10.0);
        egui::CollapsingHeader::new("Advanced")
            .default_open(false)
            .show(ui, |ui| {
                egui::Grid::new("advanced_grid")
                    .num_columns(2)
                    .striped(false)
                    .min_col_width(120.0)
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("Cipher")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                        ui.label(
                            egui::RichText::new("AES-256-GCM-SIV (RFC 8452)")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_MED),
                        );
                        ui.end_row();

                        ui.label(
                            egui::RichText::new("Streaming")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                        ui.label(
                            egui::RichText::new("BE32, 1 MiB chunks")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_MED),
                        );
                        ui.end_row();

                        ui.label(
                            egui::RichText::new("KDF")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                        ui.label(
                            egui::RichText::new("Argon2id (256 MiB / 3 / 4)")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_MED),
                        );
                        ui.end_row();

                        ui.label(
                            egui::RichText::new("Key expansion")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                        ui.label(
                            egui::RichText::new("HKDF-SHA512")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_MED),
                        );
                        ui.end_row();

                        ui.label(
                            egui::RichText::new("Format")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                        ui.label(
                            egui::RichText::new("VAULTX04 (with header AAD)")
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_MED),
                        );
                        ui.end_row();
                    });
            });

        if self.mode == Mode::Encrypt
            && self
                .selected_file
                .as_ref()
                .is_some_and(|path| is_vx2_file(path))
        {
            ui.add_space(14.0);
            egui::Frame::new()
                .fill(Palette::warning_muted())
                .stroke(Stroke::new(1.0_f32, Palette::WARNING))
                .corner_radius(8.0)
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("Re-encrypting an existing .vx2 file")
                            .font(FontId::new(11.0, FontFamily::Monospace))
                            .color(Palette::WARNING)
                            .strong(),
                    );
                    ui.add_space(6.0);
                    ui.checkbox(
                        &mut self.reencrypt_confirmed,
                        "I understand this will encrypt a file that is already encrypted.",
                    );
                });
        }

        if let Some(status) = &self.status {
            ui.add_space(14.0);
            self.draw_notice(
                ui,
                "Status",
                status,
                Palette::SURFACE_1,
                Palette::BORDER,
                Palette::TEXT_ACCENT,
            );
        }

        ui.add_space(20.0);

        let mismatch = self.mode == Mode::Encrypt
            && !self.password.is_empty()
            && !self.confirm_password.is_empty()
            && !constant_time_eq(self.password.as_bytes(), self.confirm_password.as_bytes());
        let disabled = self.password.chars().count() < crypto::MIN_PASSWORD_LEN
            || mismatch
            || (self.mode == Mode::Encrypt
                && self
                    .selected_file
                    .as_ref()
                    .is_some_and(|path| is_vx2_file(path))
                && !self.reencrypt_confirmed);

        let is_vx2 = self.selected_file.as_ref().is_some_and(|p| is_vx2_file(p));

        if is_vx2 {
            let decrypt_disabled = self.password.chars().count() < crypto::MIN_PASSWORD_LEN;
            if self
                .draw_button(
                    ui,
                    "DECRYPT",
                    vec2(ui.available_width(), 44.0),
                    ButtonKind::Primary,
                    !decrypt_disabled,
                )
                .clicked()
                && !decrypt_disabled
            {
                self.execute(ctx);
            }
        } else if self
            .draw_button(
                ui,
                "ENCRYPT",
                vec2(ui.available_width(), 44.0),
                ButtonKind::Primary,
                !disabled,
            )
            .clicked()
            && !disabled
        {
            self.execute(ctx);
        }
    }

    fn draw_progress_meter(&self, ui: &mut egui::Ui) {
        let (bar_rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 7.0), Sense::hover());
        let painter = ui.painter_at(bar_rect);
        painter.rect_filled(bar_rect, 4.0, Palette::SURFACE_HI);
        painter.rect_filled(
            Rect::from_min_max(
                bar_rect.min,
                Pos2::new(
                    bar_rect.min.x + bar_rect.width() * self.prog_frac,
                    bar_rect.max.y,
                ),
            ),
            4.0,
            Palette::ACCENT,
        );
    }

    fn draw_processing(&mut self, ui: &mut egui::Ui) {
        let spinner = ["|", "/", "-", "\\"];
        let percent = (self.prog_frac * 100.0).round() as u32;
        let action_text = match self.mode {
            Mode::Encrypt => "Encrypting...",
            Mode::Decrypt => "Decrypting...",
        };
        let filename = self
            .selected_file
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("(unknown file)"));

        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new(spinner[self.spinner_index % spinner.len()])
                    .font(FontId::new(28.0, FontFamily::Monospace))
                    .color(Palette::ACCENT),
            );
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!("{percent}%"))
                    .font(FontId::new(26.0, FontFamily::Monospace))
                    .color(Palette::TEXT_HI)
                    .strong(),
            );
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new(action_text)
                    .font(FontId::new(16.0, FontFamily::Monospace))
                    .color(Palette::TEXT_HI)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(truncate_chars(&filename, 40))
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .color(Palette::TEXT_MED),
            );
        });

        ui.add_space(16.0);
        self.draw_progress_meter(ui);
        ui.add_space(14.0);

        ui.label(
            egui::RichText::new(truncate_chars(
                self.status
                    .as_deref()
                    .unwrap_or("Processing your file locally."),
                72,
            ))
            .font(FontId::new(11.0, FontFamily::Monospace))
            .color(Palette::TEXT_MED),
        );
        ui.add_space(14.0);

        // P2-UI: Removed the scramble-text "ACTIVITY" panel — it was decorative
        // CPU burn that read as a movie prop (anti-pattern per UI research §5).
        // The progress %, status line, and Cancel button are all the user needs.

        // P1-2: Cancel button — sets the cancel_flag, which the crypto thread
        // polls at every chunk boundary. The thread then cleans up its .tmp
        // file and returns CryptoError::Cancelled, which the message handler
        // in update() converts into a "Cancelled by user" status.
        ui.vertical_centered(|ui| {
            let cancel_btn = egui::Button::new(
                egui::RichText::new("CANCEL")
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .color(Palette::TEXT_HI),
            )
            .fill(Palette::SURFACE_2)
            .stroke(Stroke::new(1.0_f32, Palette::BORDER))
            .corner_radius(6.0)
            .min_size(egui::vec2(140.0, 32.0));

            if ui.add(cancel_btn).clicked() {
                self.cancel_flag.store(true, Ordering::SeqCst);
                self.status = Some("Cancelling after current chunk...".to_owned());
            }
        });

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Cancel takes effect after the current 1 MB chunk completes.")
                .font(FontId::new(10.5, FontFamily::Monospace))
                .color(Palette::TEXT_LO),
        );
    }

    fn draw_result(&mut self, ui: &mut egui::Ui, ok: bool) {
        ui.add_space(18.0);
        ui.vertical_centered(|ui| {
            let (icon_rect, _) = ui.allocate_exact_size(vec2(82.0, 82.0), Sense::hover());
            let painter = ui.painter_at(icon_rect);
            let fill = if ok {
                Palette::success_muted()
            } else {
                Palette::error_muted()
            };
            let stroke = if ok { Palette::SUCCESS } else { Palette::ERROR };
            painter.circle_filled(icon_rect.center(), 30.0, fill);
            painter.circle_stroke(icon_rect.center(), 30.0_f32, Stroke::new(2.0_f32, stroke));

            if ok {
                self.check_anim = (self.check_anim + 0.07).min(1.0);
                let a = Pos2::new(icon_rect.min.x + 18.0, icon_rect.min.y + 43.0);
                let b = Pos2::new(icon_rect.min.x + 33.0, icon_rect.min.y + 57.0);
                let c = Pos2::new(icon_rect.min.x + 61.0, icon_rect.min.y + 28.0);
                painter.add(Shape::line(
                    vec![a, b, c],
                    Stroke::new(2.5_f32, Palette::SUCCESS),
                ));
            } else {
                painter.line_segment(
                    [
                        icon_rect.center() + vec2(-13.0, -13.0),
                        icon_rect.center() + vec2(13.0, 13.0),
                    ],
                    Stroke::new(2.5_f32, Palette::ERROR),
                );
                painter.line_segment(
                    [
                        icon_rect.center() + vec2(13.0, -13.0),
                        icon_rect.center() + vec2(-13.0, 13.0),
                    ],
                    Stroke::new(2.5_f32, Palette::ERROR),
                );
            }
        });

        ui.vertical_centered(|ui| {
            if let Some(dest) = &self.dest_path {
                let file_name = dest
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| String::from("(output file)"));
                ui.label(
                    egui::RichText::new(truncate_chars(&file_name, 44))
                        .font(FontId::new(12.0, FontFamily::Monospace))
                        .color(Palette::TEXT_MED),
                );
                ui.add_space(14.0);
            }

            // P2-UI: Move SHA-256 hash into a collapsed "Details" section so it
            // doesn't clutter the success screen. Per UI research §7.3, the hash
            // is a post-operation verifier, not a status indicator.
            if let Some(hash) = &self.sha256_hash {
                ui.add_space(8.0);
                egui::CollapsingHeader::new("Details")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("SHA-256 (output file)")
                                .font(FontId::new(9.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                        ui.add_space(2.0);
                        let hash_display = if hash.len() > 48 {
                            format!("{}...{}", &hash[..24], &hash[hash.len() - 24..])
                        } else {
                            hash.clone()
                        };
                        ui.label(
                            egui::RichText::new(hash_display)
                                .font(FontId::new(10.5, FontFamily::Monospace))
                                .color(Palette::TEXT_LO),
                        );
                    });
                ui.add_space(8.0);
            }

            if ok {
                let button_width = (ui.available_width() - 8.0) * 0.5;
                ui.horizontal(|ui| {
                    if self
                        .draw_button(
                            ui,
                            "Open folder",
                            vec2(button_width, 40.0),
                            ButtonKind::Secondary,
                            true,
                        )
                        .clicked()
                    {
                        if let Some(dest) = &self.dest_path {
                            if let Some(parent) = dest.parent() {
                                let _ = open::that(parent);
                            }
                        }
                    }

                    if self
                        .draw_button(
                            ui,
                            "New file",
                            vec2(button_width, 40.0),
                            ButtonKind::Primary,
                            true,
                        )
                        .clicked()
                    {
                        self.secure_wipe_session(ui.ctx());
                    }
                });
            } else {
                if let Some(message) = &self.status {
                    self.draw_notice(
                        ui,
                        "Error details",
                        &truncate_chars(message, 120),
                        Palette::error_muted(),
                        Palette::ERROR,
                        Palette::ERROR,
                    );
                    ui.add_space(14.0);
                }

                if self
                    .draw_button(
                        ui,
                        "Back to start",
                        vec2(ui.available_width(), 40.0),
                        ButtonKind::Primary,
                        true,
                    )
                    .clicked()
                {
                    self.secure_wipe_session(ui.ctx());
                }
            }
        });
    }

    fn draw_batch_configure(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        strength_label: &str,
    ) {
        ui.horizontal(|ui| {
            if self
                .draw_button(ui, "< Back", vec2(92.0, 34.0), ButtonKind::Secondary, true)
                .clicked()
            {
                self.secure_wipe_session(ctx);
            }
        });

        ui.add_space(16.0);
        let files_count = self.batch_files.len();
        self.draw_notice(
            ui,
            &format!("{files_count} files selected"),
            "All files will be processed with the same passphrase.",
            Palette::SURFACE_1,
            Palette::BORDER,
            Palette::TEXT_MED,
        );

        ui.add_space(18.0);
        self.draw_password_row(ui, "Batch passphrase", true);

        if self.mode == Mode::Encrypt {
            ui.add_space(12.0);
            self.draw_password_row(ui, "Confirm passphrase", false);

            if !self.password.is_empty()
                && !self.confirm_password.is_empty()
                && !constant_time_eq(self.password.as_bytes(), self.confirm_password.as_bytes())
            {
                ui.add_space(8.0);
                self.draw_notice(
                    ui,
                    "Passphrases do not match",
                    "Please ensure both fields contain the exact same text.",
                    Palette::error_muted(),
                    Palette::ERROR,
                    Palette::ERROR,
                );
            }
        }

        ui.add_space(12.0);
        self.draw_strength_meter(ui, strength_label);

        ui.add_space(20.0);
        let mut enabled = self.password.chars().count() >= crypto::MIN_PASSWORD_LEN;
        if self.mode == Mode::Encrypt {
            enabled &= constant_time_eq(self.password.as_bytes(), self.confirm_password.as_bytes());
        }

        if let Some(msg) = &self.status {
            ui.add_space(8.0);
            self.draw_notice(
                ui,
                "Notice",
                msg,
                Palette::warning_muted(),
                Palette::WARNING,
                Palette::WARNING,
            );
            ui.add_space(12.0);
        }

        let button_label = if self.mode == Mode::Encrypt {
            "Encrypt All Files"
        } else {
            "Decrypt All Files"
        };

        if self
            .draw_button(
                ui,
                button_label,
                vec2(ui.available_width(), 44.0),
                ButtonKind::Primary,
                enabled,
            )
            .clicked()
            && enabled
        {
            self.execute_batch(ctx);
        }
    }

    fn draw_batch_processing(&mut self, ui: &mut egui::Ui) {
        let files_count = self.batch_files.len();
        let idx = self.batch_current_index;

        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            ui.label(
                egui::RichText::new(spinner[self.spinner_index % spinner.len()])
                    .font(FontId::new(28.0, FontFamily::Monospace))
                    .color(Palette::ACCENT),
            );
            ui.add_space(20.0);

            let current_file_name = self
                .batch_files
                .get(idx)
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            ui.label(
                egui::RichText::new(format!("Processing file {} of {}", idx + 1, files_count))
                    .font(FontId::new(14.0, FontFamily::Monospace))
                    .color(Palette::TEXT_HI)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(truncate_chars(&current_file_name, 50))
                    .font(FontId::new(11.0, FontFamily::Monospace))
                    .color(Palette::TEXT_MED),
            );

            ui.add_space(20.0);

            // Overall progress
            let (rect, _) = ui.allocate_exact_size(vec2(320.0, 6.0), Sense::hover());
            let painter = ui.painter_at(rect);
            painter.rect_filled(rect, 3.0, Palette::SURFACE_2);
            let p_width = rect.width() * self.prog_frac;
            if p_width > 0.0 {
                let p_rect =
                    Rect::from_min_max(rect.min, Pos2::new(rect.min.x + p_width, rect.max.y));
                painter.rect_filled(p_rect, 3.0, Palette::ACCENT);
            }

            ui.add_space(16.0);

            // Current file progress text
            if let Some(status) = &self.status {
                ui.label(
                    egui::RichText::new(status)
                        .font(FontId::new(10.5, FontFamily::Monospace))
                        .color(Palette::TEXT_LO),
                );
            }

            ui.add_space(24.0);
            if self
                .draw_button(ui, "Cancel", vec2(120.0, 36.0), ButtonKind::Secondary, true)
                .clicked()
            {
                self.cancel_flag.store(true, Ordering::SeqCst);
                self.status = Some("Canceling operation...".to_owned());
            }
        });
    }

    fn draw_batch_result(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);

            let total = self.batch_results.len();
            let success_count = self
                .batch_results
                .iter()
                .filter(|r| r.dest_path.is_some())
                .count();
            let has_errors = success_count < total;

            let (icon_color, msg) = if success_count == total {
                (
                    Palette::SUCCESS,
                    format!("Successfully processed all {total} files."),
                )
            } else if success_count > 0 {
                (
                    Palette::WARNING,
                    format!("Processed {success_count} of {total} files. Some failed."),
                )
            } else {
                (Palette::ERROR, "All files failed to process.".to_string())
            };

            // Draw generic icon
            let (rect, _) = ui.allocate_exact_size(vec2(48.0, 48.0), Sense::hover());
            let painter = ui.painter_at(rect);
            painter.circle_filled(rect.center(), 24.0, icon_color);
            painter.text(
                rect.center(),
                Align2::CENTER_CENTER,
                if has_errors { "!" } else { "✓" },
                FontId::new(24.0, FontFamily::Monospace),
                Palette::SURFACE,
            );

            ui.add_space(16.0);
            ui.label(
                egui::RichText::new(msg)
                    .font(FontId::new(14.0, FontFamily::Monospace))
                    .color(Palette::TEXT_HI)
                    .strong(),
            );

            ui.add_space(16.0);

            // Scrollable list of results
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    for res in &self.batch_results {
                        ui.horizontal(|ui| {
                            if let Some(err) = &res.error {
                                ui.label(egui::RichText::new("✗").color(Palette::ERROR));
                                ui.label(
                                    egui::RichText::new(truncate_chars(&res.src_name, 30))
                                        .color(Palette::TEXT_MED),
                                );
                                ui.label(
                                    egui::RichText::new(truncate_chars(err, 30))
                                        .color(Palette::ERROR)
                                        .size(10.0),
                                );
                            } else {
                                ui.label(egui::RichText::new("✓").color(Palette::SUCCESS));
                                ui.label(
                                    egui::RichText::new(truncate_chars(&res.src_name, 30))
                                        .color(Palette::TEXT_MED),
                                );
                                if let Some(hash) = &res.sha256 {
                                    let short = if hash.len() > 16 {
                                        format!("{}...", &hash[..16])
                                    } else {
                                        hash.clone()
                                    };
                                    ui.label(
                                        egui::RichText::new(short)
                                            .color(Palette::TEXT_LO)
                                            .size(9.0)
                                            .font(FontId::new(9.0, FontFamily::Monospace)),
                                    );
                                }
                            }
                        });
                        ui.add_space(4.0);
                    }
                });

            ui.add_space(20.0);
            if self
                .draw_button(
                    ui,
                    "Back to start",
                    vec2(ui.available_width(), 40.0),
                    ButtonKind::Primary,
                    true,
                )
                .clicked()
            {
                self.secure_wipe_session(ui.ctx());
            }
        });
    }
}

impl eframe::App for NeuronEncryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(path) = dropped_files.first().and_then(|file| file.path.clone()) {
            // P1-3: ignore drops while an operation is in progress; the background
            // thread is still writing the original output and accepting a new file
            // mid-flight would corrupt the on-screen state (old dest shown with new
            // selected_file). Queueing would be nicer, but simply ignoring is safe.
            let busy = matches!(self.flow, AppFlow::Processing | AppFlow::BatchProcessing);
            if !busy {
                self.set_selected_file(path);
            }
        }

        loop {
            let msg = self.crypto_rx.as_ref().and_then(|rx| rx.try_recv().ok());
            let Some(msg) = msg else {
                break;
            };
            match msg {
                GuiMsg::Progress(progress, text) => {
                    self.progress = progress;
                    self.status = Some(truncate_chars(&sanitize_text(&text), 72));
                }
                GuiMsg::Done(message, hash) => {
                    if self.cancel_flag.load(Ordering::SeqCst) {
                        self.secure_wipe_session(ctx);
                    } else {
                        self.status = Some(sanitize_text(&message));
                        self.sha256_hash = hash;
                        self.flow = AppFlow::Success;
                        self.check_anim = 0.0;
                    }
                    self.crypto_rx = None;
                }
                GuiMsg::Error(error) => {
                    if self.cancel_flag.load(Ordering::SeqCst) {
                        self.secure_wipe_session(ctx);
                    } else {
                        self.status = Some(sanitize_text(&error.to_string()));
                        self.flow = AppFlow::Failure;
                    }
                    self.crypto_rx = None;
                }
                GuiMsg::BatchFileProgress(idx, progress, msg) => {
                    self.batch_current_index = idx;
                    self.batch_current_file_progress = progress;
                    self.status = Some(truncate_chars(&sanitize_text(&msg), 72));
                }
                GuiMsg::BatchFileDone(idx, dest_path, hash) => {
                    if let Some(res) = self.batch_results.get_mut(idx) {
                        res.dest_path = Some(dest_path);
                        res.sha256 = hash;
                    }
                }
                GuiMsg::BatchFileError(idx, err_msg) => {
                    if let Some(res) = self.batch_results.get_mut(idx) {
                        res.error = Some(err_msg);
                    }
                }
                GuiMsg::BatchAllDone => {
                    if self.cancel_flag.load(Ordering::SeqCst) {
                        self.secure_wipe_session(ctx);
                    } else {
                        self.flow = AppFlow::BatchDone;
                        self.check_anim = 0.0;
                    }
                    self.crypto_rx = None;
                }
            }
        }

        let (_, target_strength, strength_label) = eval_strength(&self.password);
        self.strength_frac += (target_strength - self.strength_frac) * 0.18;
        if (target_strength - self.strength_frac).abs() > 0.003 {
            ctx.request_repaint_after(Duration::from_millis(32));
        }

        if self.flow == AppFlow::Processing || self.flow == AppFlow::BatchProcessing {
            if Instant::now().duration_since(self.last_spinner_tick) >= Duration::from_millis(80) {
                self.last_spinner_tick = Instant::now();
                self.spinner_index = (self.spinner_index + 1) % 4;
                // P2-UI: scramble_text generation removed — the ACTIVITY panel
                // that consumed it is gone. Saves CPU and RNG calls per frame.
            }

            self.prog_frac += (self.progress - self.prog_frac) * 0.15;
            ctx.request_repaint_after(Duration::from_millis(16));
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(Palette::BG))
            .show(ctx, |ui| {
                self.draw_title_bar(ui);
                ui.add_space(22.0);

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        egui::Frame::new()
                            .fill(Palette::SURFACE)
                            .stroke(Stroke::new(1.0_f32, Palette::BORDER))
                            .corner_radius(12.0)
                            .inner_margin(24.0)
                            .show(ui, |ui| {
                                ui.set_width(520.0);
                                self.draw_screen_header(ui);
                                ui.add_space(22.0);

                                match self.flow {
                                    AppFlow::FileDrop => self.draw_file_drop(ui),
                                    AppFlow::Configure => {
                                        self.draw_configure(ui, ctx, strength_label)
                                    }
                                    AppFlow::Processing => self.draw_processing(ui),
                                    AppFlow::Success => self.draw_result(ui, true),
                                    AppFlow::Failure => self.draw_result(ui, false),
                                    AppFlow::BatchConfigure => {
                                        self.draw_batch_configure(ui, ctx, strength_label)
                                    }
                                    AppFlow::BatchProcessing => self.draw_batch_processing(ui),
                                    AppFlow::BatchDone => self.draw_batch_result(ui),
                                }
                            });

                        ui.add_space(10.0);
                        // P2-UI: Removed version stamp + GitHub link from bottom of every
                        // screen. Version belongs in About (accessible via title bar dot),
                        // not on every screen. Reduces visual clutter.
                    });
                });
            });
    }
}
