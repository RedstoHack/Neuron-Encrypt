# CLI Improvement Plan

This document tracks known issues and planned improvements for the `neuron-encrypt-cli` binary, based on the post-publish code review of `neuron-encrypt/src/bin/cli.rs`.

---

## Medium Priority

These issues affect maintainability and could become functional bugs under load or in automation pipelines.

### 1. Extract helpers from the oversized `run()` function

**Problem:** `run()` is ~460 lines with two near-identical branches for file I/O vs. pipe/stream. Password validation, reporter setup, cipher dispatch, elapsed-time calculation, success messaging, and a 30-line `match result` block are copy-pasted between the two paths.

**Proposed fix:** Split into `run_file()` / `run_stream()` and extract shared helpers:
- `setup_reporter(total, mode)` → `Box<dyn ProgressReporter>`
- `emit_success_json(...)` / `emit_error_json(...)`
- `handle_crypto_result(result, mode, output_path, start, cli, source_size)` → unified success/error flow

### 2. Centralize JSON error emission

**Problem:** The pattern of constructing `JsonResult { status: "error", error: Some(msg), duration_ms: start.elapsed().as_millis(), .. }` and calling `emit_json` is repeated ~12 times. A future maintainer could easily forget to populate `sha256` or `output_path` in one branch, producing inconsistent JSON for CI/CD consumers.

**Proposed fix:** Add a single helper:

```rust
fn err_json(start: &Instant, output: Option<PathBuf>, msg: impl Into<String>) -> JsonResult
```

and use it everywhere instead of inline `JsonResult { ... }` literals.

### 3. Fix unbounded stdin buffer when decrypting from pipe

**Problem:** When decrypting with `-i -`, the entire piped input is read into a `Vec::new()` and wrapped in `io::Cursor::new`. This bypasses the existing chunked streaming path in `crypto::decrypt_stream` and can OOM on large inputs.

**Proposed fix:** Implement a bounded, seekable adapter or use `tempfile` to spill buffered stdin before handing it to the streaming decrypter. At minimum, document the limitation and enforce a configurable size cap.

---

## Low Priority

These are edge-case polish items that improve automation reliability and internal consistency.

### 4. Document (and clamp) the `ProgressReporter::report` progress range

**Problem:** `IndProgress::report` uses `((progress - 0.10).max(0.0) / 0.85 * total)` which implies a convention that crypto reports progress ~0.10–0.95, where 0.0–0.10 covers KDF. This convention is undocumented, and if `progress >= 1.0`, the bar position can exceed 100%.

**Proposed fix:** Document the expected `[0.0, 1.0]` range in `ProgressReporter`, clarify the KDF-warmup phase, and clamp the bar position to `total_bytes`.

### 5. Merge or clarify `check_output_exists` vs. `remove_existing_output_if_forced`

**Problem:** Both functions inspect `output_path.exists()` and `force`, and both emit similar error messages. A future change to one path (e.g., changing the stderr text or JSON shape) could be accidentally missed in the other.

**Proposed fix:** Merge into a single `validate_output_path(path, force, json)` check that returns a structured outcome, or extract a shared `conflict_msg(path)` helper to guarantee consistent messaging.

### 6. Make stream-mode JSON output_path deterministic

**Problem:** When outputting to stdout (`-o -`), the success JSON sets `output_path: None`. Automation consumers cannot distinguish "stdout was the destination" from "no destination was set."

**Proposed fix:** Set `output_path: Some("-".into())` for pipe/stdout destinations so downstream tooling has a deterministic value.
