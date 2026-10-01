---
Task ID: 5
Agent: Crypto Security Deep-Review
Task: Deep manual cryptographic security audit of Neuron-Encrypt core (crypto.rs, error.rs, utils.rs, Cargo.toml)

Work Log:
- Read crypto.rs (1364 lines), error.rs (62 lines), utils.rs (56 lines), Cargo.toml, Cargo.lock
- Verified Argon2id params at derive_key (line 163) and derive_key_v3 (line 183): `Params::new(262_144, 3, 4, Some(64))` = 256 MiB / 3 iter / 4 lanes / 64-byte output, Algorithm::Argon2id, Version::V0x13 — RFC 9106 compliant
- Verified AES-256-GCM-SIV usage in V2 (`encrypt_bytes`/`decrypt_bytes`/`decrypt_file_legacy`/`decrypt_stream_v2`) — single-shot `Aead::encrypt`/`decrypt` with `Payload{msg, aad}`
- Verified AES-256-GCM-SIV usage in V3 (`encrypt_file`/`decrypt_file_streaming`/`encrypt_stream`/`decrypt_stream_v3`) — `EncryptorBE32`/`DecryptorBE32` from `aead::stream`
- Checked AAD construction in both paths: V2 uses `build_aad(salt, nonce)` = salt||nonce; V3 uses NO AAD (verified by inspecting all `encrypt_next`/`encrypt_last`/`decrypt_next`/`decrypt_last` call sites — they all pass `&[u8]` which converts to `Payload{msg, aad: &[]}`)
- Checked nonce/salt randomness: every salt and nonce is freshly `OsRng.fill_bytes(...)` per call (lines 322-323, 412-413, 840-841)
- Analyzed chunk-level integrity: truncation, reorder, chunk-substitution, and extension attacks all fail due to GCM-SIV tag verification + BE32 flag/counter protection (verified by tracing V3 encrypt→decrypt roundtrip)
- Checked Zeroizing coverage on all secret buffers (key, intermediate, plaintext chunks, encrypt-side plaintext buf, decrypt-side plaintext pt) — comprehensive
- Analyzed error-side-channel risks: wrong password and corrupted file both produce `CryptoError::DecryptionFailed` — no distinguishable error
- Checked test coverage gaps: 13 tests exist, but no empty-file / single-byte / truncation / tampering / reorder / counter-boundary / Argon2id-param-verification tests
- Verified dependency versions in Cargo.lock: aes-gcm-siv 0.11.1, aead 0.5.2, argon2 0.5.3, hkdf 0.12.4, sha2 0.10.9, zeroize 1.8.2, rand_core 0.6.4 — all RustCrypto, no known CVEs

Stage Summary:

### [MEDIUM] Finding 5-1: V3 streaming omits AAD — salt and stream_nonce not explicitly authenticated
- **Location**: crypto.rs:419, 453-454, 474-476, 482-484 (encrypt_file); 681, 718-720, 731-733 (decrypt_file_streaming); 847, 862-864, 885-887, 892-894 (encrypt_stream); 958, 981-983, 993-995 (decrypt_stream_v3)
- **Category**: crypto-correctness / format-robustness
- **Description**: V2 correctly calls `build_aad(salt, nonce)` (line 196-201) and passes it as `Payload{aad: &aad}`. V3 streaming never invokes `build_aad` — every `encrypt_next`/`encrypt_last`/`decrypt_next`/`decrypt_last` call passes a bare `&[u8]` slice, which `impl Into<Payload>` converts to `Payload{msg, aad: &[]}`. So the 16-byte salt, the 7-byte stream_nonce, and the 8-byte magic are written to the file in plaintext but are NOT covered by any AEAD tag.
- **Impact**: Investigated carefully. Tampering with the salt changes the derived Argon2id+HKDF key, so all chunk tags fail verification (`DecryptionFailed`). Tampering with the stream_nonce changes the AEAD nonce prefix, so all chunk tags fail verification. So in practice the salt+nonce ARE implicitly authenticated through their effect on the cipher state — an attacker cannot modify them and produce a file that decrypts to anything other than failure. The best-practice violation (defensive-in-depth: authenticate the full header in AAD so future refactors that touch key derivation cannot accidentally strip the implicit authentication) is real but the immediate exploitability is limited to a no-op DoS indistinguishable from "wrong password".
- **Verification**: Read all 4 V3 encrypt/decrypt paths; confirmed zero `Payload` literals with non-empty `aad` field; confirmed `EncryptorBE32::from_aead(cipher, (&stream_nonce).into())` only seeds the nonce prefix, not the AAD.
- **Suggested fix**: Derive a one-time AAD per file: `let aad = build_aad_v3(&salt, &stream_nonce);` (extend `build_aad` to also include `MAGIC_V3`), then pass `Payload{msg: &buf[..n], aad: &aad}` to every `encrypt_next`/`encrypt_last`/`decrypt_next`/`decrypt_last` call. This is a breaking format change so bump to V4 or re-use V3 with a feature flag.
- **Confidence**: High (the observation is certain; the practical exploitability is limited as analyzed)

### [MEDIUM] Finding 5-2: V3 streaming has no enforcement of 4 TB max file size — counter overflow → nonce reuse
- **Location**: crypto.rs:395-511 (encrypt_file), 827-910 (encrypt_stream)
- **Category**: crypto-correctness / format-robustness
- **Description**: `EncryptorBE32` internally uses a 4-byte (32-bit) counter for chunk indexing, so the maximum number of chunks is 2^32. At `CHUNK_SIZE = 1_048_576` bytes (1 MiB), the maximum file size before counter wraparound is 2^32 × 1 MiB = 4 TiB. `encrypt_file` and `encrypt_stream` never check `source_len` against this limit. If a future user encrypts a >4 TiB file (large databases, video archives, scientific datasets), the counter wraps to 0, chunk N and chunk N+2^32 are encrypted with the same (key, nonce, counter) triple — catastrophic nonce reuse that breaks confidentiality and integrity of GCM-SIV.
- **Impact**: An attacker observing a >4 TiB encrypted file can XOR corresponding chunks to recover plaintext XOR plaintext', and may be able to forge tags. Realistic only for very large files, but the failure mode is silent and catastrophic.
- **Verification**: `MAX_FILE_SIZE = 8_000_000_000` (line 61) is only enforced for V2 (`MAX_ENCRYPTED_FILE_SIZE` at line 62, checked at line 572). No equivalent check exists in `encrypt_file` or `encrypt_stream` for V3. `chunk_counter: u64` at line 446 is only used for the I/O governor sleep cadence, not for nonce counter overflow detection.
- **Suggested fix**: At the top of `encrypt_file` and `encrypt_stream`, after computing `source_len`, add `const MAX_V3_FILE_SIZE: u64 = (1u64 << 32) * CHUNK_SIZE as u64; if source_len > MAX_V3_FILE_SIZE { return Err(CryptoError::FileTooLarge{...}); }`. Document the 4 TiB limit in the header comment.
- **Confidence**: High

### [MEDIUM] Finding 5-3: Test coverage gaps — missing edge-case and adversarial tests
- **Location**: crypto.rs:1049-1364 (`#[cfg(test)] mod tests`)
- **Category**: test-gap
- **Description**: 13 tests cover: happy-path bytes roundtrip, happy-path file roundtrip, password-too-short, invalid-magic, output-name helpers, nonce-length rejection, existing-destination rejection, overwrite-with-force, same-src-dest rejection, multi-chunk V3 roundtrip, exact-chunk V3 roundtrip, wrong-password, header-only-input rejection, V2 backward-compat. **Missing**: empty-file (0 bytes) roundtrip; single-byte file roundtrip; file of `CHUNK_SIZE - 1` bytes; file of `CHUNK_SIZE + 1` bytes; truncated ciphertext (truncation attack); tampered salt/nonce; tampered chunk byte; reordered chunks; chunk-substitution from another file; V2↔V3 cross-format confusion; >4 TiB counter-boundary rejection; Argon2id param verification (assert `m=262144, t=3, p=4, output=64`); HKDF info-string domain separation (V2 vs V3 produce different keys for same password+salt).
- **Impact**: Regressions in any of the above adversarial/edge scenarios would ship undetected. The truncation/reorder/tamper tests are particularly important because they verify the security claims of the V3 streaming format.
- **Verification**: Read the entire test module (lines 1049-1364); enumerated what is tested vs. not.
- **Suggested fix**: Add the missing tests. Each is <30 lines. Prioritize: empty-file roundtrip, truncated-ciphertext rejection, tampered-chunk rejection, reordered-chunk rejection, and Argon2id-param-verification (read back the `Params` if API permits, otherwise hard-code a known-good Argon2id output vector).
- **Confidence**: High

### [LOW] Finding 5-4: Inconsistent 1 GB limit check between V2 file and V2 stream decrypt paths
- **Location**: crypto.rs:581-584 (`decrypt_file_legacy`) vs 1022-1029 (`decrypt_stream_v2`)
- **Category**: format-robustness / consistency
- **Description**: `decrypt_file_legacy` uses `read_limited_file(file, 1_073_741_824u64)` which internally calls `file.take(limit + 1)` (line 260) so it can read up to 1 GiB + 1 byte, then checks `raw.len() as u64 > 1_073_741_824u64` (line 582) — strict greater-than. A 1 GiB body passes. `decrypt_stream_v2` uses `reader.take(V2_STREAM_MAX_BYTES).read_to_end(...)` (line 1025) — caps the read at exactly 1 GiB — then checks `ciphertext.len() as u64 >= V2_STREAM_MAX_BYTES` (line 1027) — greater-than-or-equal. A 1 GiB body FAILS with `LegacyFileTooLarge`. So the same 1 GiB V2 file decrypts successfully via `neuron-encrypt decrypt file.vx2` (CLI/GUI uses `decrypt_file` → `decrypt_file_legacy`) but fails via `cat file.vx2 | neuron-encrypt decrypt -` (pipe uses `decrypt_stream` → `decrypt_stream_v2`).
- **Impact**: Inconsistent behavior between CLI file-mode and CLI pipe-mode for V2 files exactly at the 1 GiB boundary. A user scripting `decrypt - < file.vx2` will see `LegacyFileTooLarge` where `decrypt file.vx2` would succeed. No confidentiality impact.
- **Verification**: Read both functions; traced the `take(limit + 1)` vs `take(V2_STREAM_MAX_BYTES)` and the `>` vs `>=` boundary checks.
- **Suggested fix**: Make both paths use the same limit and the same comparison. Recommend changing `decrypt_stream_v2` to `reader.take(V2_STREAM_MAX_BYTES + 1)` and `if ciphertext.len() as u64 > V2_STREAM_MAX_BYTES`. Or document that the streaming path's limit is 1 byte tighter.
- **Confidence**: High

### [LOW] Finding 5-5: `constant_time_eq` iterates over `max(len_a, len_b)` — leaks the longer length
- **Location**: utils.rs:1-20
- **Category**: side-channel
- **Description**: The loop at line 8 runs `0..max_len` where `max_len = len_a.max(len_b)`. The number of loop iterations is observable via timing and is proportional to the longer of the two input lengths. The length comparison itself uses a constant-time bit trick (line 14-15), but the loop already leaked the length. Additionally, `a.get(i).unwrap_or(&0)` and `b.get(i).unwrap_or(&0)` introduce a data-dependent branch (the `Option` discriminant) per iteration — though LLVM may compile this to a branchless `cmov`.
- **Impact**: Minor. The function is only called from `gui.rs` (lines 413, 507, 1150, 1211, 1530, 1550) and `cli.rs:163` to compare two user-supplied password strings during the "confirm password" prompt. The attacker already knows the length of one input (their own). The leak is the length of the OTHER input, which the attacker also typed. No secret comparison. Severity: Info-to-Low.
- **Verification**: Read utils.rs; grepped all call sites (only password-confirmation comparisons, no secret-vs-untrusted comparisons).
- **Suggested fix**: Replace with `subtle::ConstantTimeEq` from the `subtle` crate (RustCrypto), which is audited and branch-free. Or, if avoiding a new dep, document that this function is only safe for equal-status inputs and should not be used for secret comparison.
- **Confidence**: High (the observation is certain; severity is Low because of the limited call sites)

### [INFO] Finding 5-6: HKDF uses `None` salt — acceptable per RFC 5869 but a salt would be marginally stronger
- **Location**: crypto.rs:170, 189
- **Category**: crypto-correctness
- **Description**: `Hkdf::<Sha512>::new(None, &intermediate)` passes `None` for the salt argument. Per RFC 5869 §2.2, HKDF-Extract with no salt uses a string of `HashLen` zero bytes as the salt — this is the documented and approved mode. The `info` parameter (`b"VAULTX02_AES_256_GCM_SIV"` for V2, `b"VAULTX03_AES_256_GCM_SIV_STREAM"` for V3) provides domain separation. The 64-byte Argon2id output is high-entropy IKM, so the salt's role of "extracting from low-entropy IKM" is not really needed here.
- **Impact**: None. Investigated and confirmed safe.
- **Verification**: Read both `derive_key` and `derive_key_v3`. Verified `info` strings differ between versions (provides cross-version domain separation so the same Argon2id output produces different AES keys for V2 vs V3).
- **Suggested fix**: Optional: pass the per-file salt as the HKDF salt (`Hkdf::<Sha512>::new(Some(salt), &intermediate)`) for a tiny defensive-in-depth improvement. Not required.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-7: Only 32 of 64 bytes of HKDF output used — README "two subkeys" claim is stale
- **Location**: crypto.rs:160, 181 (32-byte `final_key`); derive_key/derive_key_v3 functions
- **Category**: documentation / crypto-design
- **Description**: Argon2id is asked for 64 bytes of output (`Params::new(..., Some(64))` at line 163/183). Those 64 bytes become the HKDF IKM. HKDF-SHA512 expands to a 32-byte `final_key` for AES-256. So 64 bytes of Argon2id output is fed in, 32 bytes of AES key is extracted. The README mentions "two subkeys (encryption + nonce seed)" but the code only derives one 32-byte key. The 7-byte stream_nonce and 12-byte V2 nonce are generated independently by `OsRng`, NOT derived from the KDF.
- **Impact**: None cryptographically. A single 32-byte AES-256 key is sufficient. The discrepancy is documentation-only. Deriving the nonce from the KDF would be an alternative design (deterministic nonce) but using `OsRng` is also fine and gives explicit freshness.
- **Verification**: Read both KDF functions; confirmed only `final_key[0..32]` is used; confirmed nonce is independently random.
- **Suggested fix**: Update README to remove the "two subkeys" claim, OR if the design intent was two subkeys, change to derive `final_key[0..32]` (encryption) + `nonce_seed[32..44]` (V2) / `[32..39]` (V3) and use HKDF-Expand twice with different `info` strings. Both are acceptable; the code matches the latter "single key + random nonce" design.
- **Confidence**: High (observation certain; this is a doc-vs-code mismatch, not a vuln)

### [INFO] Finding 5-8: 8-byte (64-bit) entropy for tmp filename — collision-safe for realistic workloads
- **Location**: crypto.rs:301-309 (`tmp_path`)
- **Category**: format-robustness
- **Description**: `tmp_path` generates an 8-byte random suffix via `OsRng.fill_bytes(&mut rng_bytes)` (line 303) and hex-encodes it to 16 chars. Birthday-bound collision probability: after N temp files in the same directory, ≈ N²/2^65. For N=2^20 (~1 million files in one dir), collision probability ≈ 2^-25 — negligible.
- **Impact**: None.
- **Verification**: Read the function; computed the birthday bound.
- **Suggested fix**: None required. (If a collision does occur, `OpenOptions::create_new(true)` returns `AlreadyExists` which propagates as an IO error — safe failure mode.)
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-9: `parse_header` re-checks magic bytes redundantly — harmless
- **Location**: crypto.rs:381-393 (`parse_header`); called from crypto.rs:586 (`decrypt_file_legacy`)
- **Category**: code-quality
- **Description**: `decrypt_file` (line 546) checks the magic bytes and dispatches to `decrypt_file_legacy` only if `&magic_buf == MAGIC`. `decrypt_file_legacy` then calls `parse_header` (line 586) which checks `&raw[..8] != MAGIC` again (line 385). The second check is redundant because the dispatcher already verified the magic. Not a security issue — defense in depth.
- **Impact**: None.
- **Verification**: Traced the call chain `decrypt_file` → `decrypt_file_legacy` → `parse_header`.
- **Suggested fix**: None required. (Could be cleaned up by having `parse_header` accept pre-validated magic, but the redundancy is cheap and harmless.)
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-10: `decrypt_file` opens the file twice — inefficient but not a security issue
- **Location**: crypto.rs:527-553 (`decrypt_file`)
- **Category**: code-quality
- **Description**: `decrypt_file` opens the file once to read 8 magic bytes (line 541, file handle dropped at line 544), then dispatches to `decrypt_file_streaming` or `decrypt_file_legacy`, each of which opens the file again via `open_regular_file` (lines 563, 657). TOCTOU concern: the file could be modified between the two opens. However, the second open reads the magic again indirectly (via `parse_header` for V2, or via the V3 salt/nonce), so a malicious swap between opens would either produce a parse failure or a tag failure — no bypass.
- **Impact**: None.
- **Verification**: Read the dispatcher and both callee functions.
- **Suggested fix**: Optional refactor: read the magic and pass the open `File` to the sub-function. Minor code-quality improvement.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-11: Zeroizing coverage is comprehensive — all secret buffers wrapped
- **Location**: crypto.rs (multiple)
- **Category**: key-mgmt / memory-hygiene
- **Description**: Verified the following secret buffers are `Zeroizing<T>`: `final_key` (line 160, 181), `intermediate` (line 162, 182), `ciphertext` return from `encrypt_bytes` (line 339), `plaintext` return from `decrypt_bytes`/`decrypt_file_legacy`/`decrypt_stream_v2`/`decrypt_stream_v3` (lines 378, 594, 981, 993, 1033), `buf` (plaintext read buffer) in `encrypt_file` (line 444) and `encrypt_stream` (line 854), `buf` (ciphertext read buffer) in `decrypt_file_streaming` (line 703) and `decrypt_stream_v3` (line 960), `last_chunk` (ciphertext holder) in `decrypt_file_streaming` (line 705) and `decrypt_stream_v3` (line 962), `pt` (decrypted plaintext) at lines 718, 731, 981, 993. The explicit `intermediate.zeroize()` calls at lines 173 and 192 are redundant (Zeroizing already zeroizes on drop) but harmless. The `password: &[u8]` parameter is owned by the caller; CLI wraps it in `Zeroizing<String>` and JNI zeroes the Java-side byte[].
- **Impact**: None. Investigated and confirmed safe.
- **Verification**: Read all 4 encrypt/decrypt paths plus the 2 KDF functions; enumerated every buffer holding secret material.
- **Suggested fix**: None required.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-12: All RNG uses OsRng — no thread_rng, no SmallRng, no deterministic seeding
- **Location**: crypto.rs:20 (import), 303, 322-323, 412-413, 786, 805, 840-841, 1062; utils.rs uses no RNG
- **Category**: crypto-correctness
- **Description**: Every call to randomness goes through `OsRng::fill_bytes` or `OsRng::next_u64`. No `thread_rng`, no `SmallRng`, no time-seeded `StdRng`. The `rand_core = "0.6"` crate with the `getrandom` feature defers to the OS CSPRNG (getrandom on Linux, BCryptGenRandom on Windows, SecRandomCopyBytes on macOS).
- **Impact**: None. Confirmed safe.
- **Verification**: Grepped for `OsRng`, `thread_rng`, `SmallRng`, `StdRng`, `from_seed`, `from_entropy` — only `OsRng` is used.
- **Suggested fix**: None required.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-13: Error side-channels are consistent — wrong password and corrupted file both yield `DecryptionFailed`
- **Location**: crypto.rs:376, 603, 720, 733, 983, 995, 1041; error.rs:18-19
- **Category**: side-channel
- **Description**: Every decryption failure path — wrong password, tampered ciphertext, tampered salt, tampered nonce, truncated file, extended file, reordered chunks — returns `CryptoError::DecryptionFailed` with the same string "Wrong password or corrupted file". No timing oracle distinguishes wrong-password from corrupted-file because Argon2id always runs (the slow step) before any tag check. The only pre-Argon2id rejections are: `FileTooSmall` (file size known to attacker), `InvalidMagic` (magic bytes in file, known to attacker), `FileTooLarge` (file size known to attacker), `PassphraseTooShort` (password length chosen by attacker). None of these leak anything the attacker doesn't already know.
- **Impact**: None. Confirmed safe.
- **Verification**: Read every `map_err(|_| CryptoError::DecryptionFailed)` site; traced which errors fire pre-Argon2id vs post-Argon2id.
- **Suggested fix**: None required.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-14: Chunk-level integrity defenses verified — truncation, reorder, substitution, extension all fail at tag check
- **Location**: crypto.rs:419, 453-484 (encrypt), 681, 708-735 (decrypt)
- **Category**: format-robustness
- **Description**: Traced each attack:
  - **Truncation at chunk boundary**: original "intermediate" chunk gets re-processed as `decrypt_last` (different flag byte in BE32 nonce) → tag mismatch → `DecryptionFailed`.
  - **Truncation within a chunk**: tag was computed over original length, now applies to shorter input → mismatch.
  - **Reorder two chunks**: each chunk's tag is bound to its position-counter; swapping changes the counter used for verification → mismatch.
  - **Substitute chunk N from another file**: requires same (key, nonce, counter); each file uses fresh random salt+nonce → different keys → mismatch.
  - **Extend by appending extra bytes after the last chunk**: original "last" chunk gets re-processed as `decrypt_next` (intermediate flag) → mismatch.
  - **Extend by appending a valid intermediate chunk after the last**: same as above; `decrypt_next` on the original-last chunk fails because it was sealed with `encrypt_last` flag.
  - **Empty file**: `read_exact_or_eof` returns 0 immediately → `encrypt_last(&[])` produces a 16-byte tag-only chunk → on decrypt, the 47-byte file (31 header + 16 tag) decrypts to empty plaintext. Verified.
  - **Single-byte / exact-chunk / exact-2-chunk / between-chunk files**: traced through the peek-and-seek-back loop at lines 467-496; all cases correctly route to `encrypt_next` or `encrypt_last` as appropriate.
- **Impact**: None. Confirmed safe.
- **Verification**: Read the entire V3 encrypt/decrypt loop; traced each attack scenario through the code.
- **Suggested fix**: None required. (Add explicit regression tests per Finding 5-3.)
- **Confidence**: High (confirmed safe)

### [LOW] Finding 5-15: `MIN_PASSWORD_LEN = 8` is the NIST minimum; consider 12+ for high-security posture
- **Location**: crypto.rs:65
- **Category**: policy
- **Description**: `MIN_PASSWORD_LEN = 8` is enforced everywhere (`encrypt_bytes`, `decrypt_bytes`, `encrypt_file`, `decrypt_file`, `encrypt_stream`, `decrypt_stream`). NIST SP 800-63B §5.1.1.2 says 8-char minimum is acceptable, but for high-security applications 12-16+ is increasingly recommended because offline brute-force is GPU-friendly. Combined with the strong Argon2id (256 MiB / 3 iter / 4 lanes) at ~0.3-1 sec per attempt, an 8-char random password (≈52 bits entropy) would take ~10^7 GPU-seconds ≈ 4 months on a single high-end GPU; an 8-char human password (≈30 bits) would crack in seconds.
- **Impact**: Policy concern, not a vulnerability. The KDF cost is the primary defense; password length is the secondary defense.
- **Verification**: Read line 65; checked all enforcement call sites.
- **Suggested fix**: Optionally raise to 10 or 12, or add a strength meter in the GUI. Document the threat model explicitly.
- **Confidence**: High (observation certain; severity is policy-level Low)

### [INFO] Finding 5-16: `panic = "abort"` + `unwrap_or_else(|e| e.into_inner())` for mutex poisoning is correct
- **Location**: Cargo.toml:54 (`panic = "abort"`); crypto.rs:128, 129, 148, 152 (mutex poisoning recovery)
- **Category**: code-quality / robustness
- **Description**: The release profile sets `panic = "abort"`, which means any panic in a worker thread aborts the entire process. The `ThrottledReporter` uses `Mutex<Option<Instant>>` and `Mutex<String>`; if a panic occurred while holding one of these mutexes, the mutex would become poisoned. The code at lines 128-129, 148, 152 uses `unwrap_or_else(|e| e.into_inner())` to recover from poisoning, which is the documented safe pattern. Since `panic = "abort"` doesn't actually let the poisoned-mutex scenario arise (a panic aborts before the mutex can be poisoned in another thread), this is belt-and-suspenders defense.
- **Impact**: None.
- **Verification**: Read the ThrottledReporter impl (lines 122-157).
- **Suggested fix**: None required.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-17: Dependencies are all RustCrypto — no known CVEs in direct deps
- **Location**: Cargo.toml:21-31; Cargo.lock
- **Category**: dep-audit
- **Description**: Direct crypto deps and their resolved versions: `aes-gcm-siv 0.11.1`, `aead 0.5.2`, `argon2 0.5.3`, `hkdf 0.12.4`, `sha2 0.10.9`, `zeroize 1.8.2`, `rand_core 0.6.4` (with `getrandom 0.2.17`). All from the RustCrypto org, which is well-audited. No known CVEs against these versions. The `rand_core 0.6` line is the older branch (current is 0.9.x); `getrandom 0.2` is also older (current is 0.3.x). These are not vulnerable but are no longer receiving feature updates — security fixes would still be backported. The known advisory `RUSTSEC-2024-0436` (`paste` crate, unmaintained, transitive) is informational only.
- **Impact**: None.
- **Verification**: Read Cargo.toml; grepped Cargo.lock for each direct dep version.
- **Suggested fix**: Optional: bump `rand_core` to 0.9 and `getrandom` to 0.3 in a future release to stay on the maintained branch. Not urgent.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-18: Argon2id params are RFC 9106 compliant and meet/exceed OWASP minimums
- **Location**: crypto.rs:163, 183 (`Params::new(262_144, 3, 4, Some(64))`)
- **Category**: crypto-correctness
- **Description**: Parameters: m=262144 KiB (256 MiB), t=3 iterations, p=4 lanes, output=64 bytes. RFC 9106 §4 (First Recommendation) suggests m=2 GiB / t=3 / p=4 / 32-byte output for "Argon2id". The code uses 1/8 of that memory (256 MiB) but produces 64-byte output (vs 32). OWASP Password Storage Cheat Sheet recommends Argon2id with m≥19 MiB, t≥2, p≥1 — the code exceeds all three. The 256 MiB memory cost is at the upper end of what desktop/mobile devices can tolerate (~0.5-1 sec latency), striking a reasonable usability/security balance.
- **Impact**: None. Confirmed safe.
- **Verification**: Read both KDF functions; cross-referenced RFC 9106 and OWASP guidance.
- **Suggested fix**: None required. (Note: `docs/SECURITY_DEFER.md` says 64 MiB but is stale — main branch is 256 MiB as the prompt confirmed.)
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-19: HKDF info strings provide strong domain separation between V2 and V3
- **Location**: crypto.rs:171 (`b"VAULTX02_AES_256_GCM_SIV"`), 190 (`b"VAULTX03_AES_256_GCM_SIV_STREAM"`)
- **Category**: crypto-correctness
- **Description**: The two `info` strings differ in both length and content. HKDF-SHA512 with different `info` produces computationally independent output even with identical IKM (Argon2id output). So even if a user happens to use the same password for a V2 file and a V3 file with the same salt, the AES keys are distinct — no cross-format key reuse. Combined with the per-file random salt, the domain separation is strong.
- **Impact**: None. Confirmed safe.
- **Verification**: Read both KDF functions; verified `info` strings differ.
- **Suggested fix**: None required.
- **Confidence**: High (confirmed safe)

### [INFO] Finding 5-20: V2↔V3 cross-format confusion is not possible
- **Location**: crypto.rs:546-552 (`decrypt_file` dispatcher), 933-939 (`decrypt_stream` dispatcher)
- **Category**: format-robustness
- **Description**: An attacker who rewrites a V3 file's magic bytes from `VAULTX03` to `VAULTX02` cannot get the file to decrypt successfully as V2. The V2 path reads a 52-byte header (8 magic + 32 salt + 12 nonce) and treats everything after offset 52 as a single ciphertext+tag blob. The V3 file's actual layout is 31-byte header (8 magic + 16 salt + 7 nonce) followed by streaming chunks. After the magic swap, V2's "salt" would be bytes 8-39 (16 bytes of real V3 salt + 7 bytes of V3 stream_nonce + 9 bytes of V3 ciphertext chunk 1), V2's "nonce" would be bytes 40-51 (more V3 ciphertext), and V2's "ciphertext" would start at offset 52 (mid-first-V3-chunk). The Argon2id derivation runs on garbage salt → wrong key → tag fails → `DecryptionFailed`. Same in the reverse direction (V2 magic swapped to V3) — V3 expects 7-byte stream_nonce at offset 24-30 but V2 has nonce bytes 40-51; the KDF and AEAD nonce are both wrong → tag fails.
- **Impact**: None. Confirmed safe.
- **Verification**: Traced the V2 and V3 header layouts (crypto.rs:29, 56) and the dispatcher logic.
- **Suggested fix**: None required.
- **Confidence**: High (confirmed safe)

---
Task ID: 6
Agent: Code Quality & Bug Review
Task: Audit gui.rs, main.rs, lib.rs, cli.rs, JNI lib.rs, Android Kotlin, NSIS installer, CI workflows for bugs, unsafe Rust, thread-safety, resource leaks, and lifecycle issues

Work Log:
- Read Task 5 (crypto-review) findings to avoid duplicating crypto concerns; focused on non-crypto bugs, unsafe Rust, thread-safety, resource leaks, Android lifecycle, and supply-chain/packaging.
- Read Rust desktop files: main.rs (93 lines), lib.rs (3), build.rs (15), gui.rs (1903 lines), cli.rs (832 lines), .cargo/config.toml, .cargo/deny.toml, Cargo.toml.
- Read JNI bridge: android/neuron-encrypt-jni/src/lib.rs (358 lines) + Cargo.toml (verified `cdylib`, `panic = "abort"`, no cfg gates on `std::os::fd`).
- Read Android Kotlin: CryptoService.kt, NeuronEncryptNative.kt, MainActivity.kt, Strength.kt, HomeScreen.kt, SingleFileScreen.kt (678 lines), BatchScreen.kt (608 lines), AndroidManifest.xml, ProgressListener.kt.
- Read installer/CI: neuron-encrypt.nsi (133 lines), .github/workflows/release.yml, .github/workflows/android.yml.
- Verified no bare `unwrap()`/`expect()` calls in gui.rs (all use `unwrap_or`/`unwrap_or_default`/`unwrap_or_else`).
- Verified `cancel_flag: Arc<AtomicBool>` in gui.rs is stored, reset, and loaded but never passed to `encrypt_file`/`decrypt_file` — only checked between files in batch mode (line 550) and used as a session-reset signal in the message handler (lines 1782/1793/1818).
- Verified single-file Processing screen (draw_processing, lines 1270-1356) has NO Cancel button; the UI text at line 1351 explicitly says "This run cannot be force-cancelled from the GUI once it has started."
- Verified dropped-files handler at top of update() (lines 1766-1769) runs unconditionally regardless of current AppFlow, including during Processing/BatchProcessing.
- Verified `String::from_utf8(bytes)` in cli.rs read_password (line 114) consumes the `Vec<u8>` and drops it without zeroize on the error path.
- Verified MainActivity.kt line 96 uses the deprecated `getParcelableExtra<Uri>` form (no Class argument).
- Verified CryptoService.kt calls `detachFd()` (lines 27-28, 58-59) BEFORE the JNI call, transferring fd ownership to native code; if JNI setup fails before `File::from_raw_fd` wraps the fds, the fds are leaked.
- Verified NSIS installer has no code-signing step and no binary checksum verification.
- Verified both Android WIPE buttons (SingleFileScreen.kt line 506, BatchScreen.kt line 543) trigger deletion immediately with no confirmation dialog.

Stage Summary:

### [MEDIUM] Finding 6-1: Desktop GUI single-file mode has no cancellation — once started, the user cannot abort
- **Location**: gui.rs:400-491 (execute), 1270-1356 (draw_processing), 446 (cancel_flag reset but never passed to encrypt_file)
- **Category**: ux-safety / error-handling
- **Description**: The `cancel_flag: Arc<AtomicBool>` field exists on `NeuronEncryptApp` (line 161) and is reset to `false` in `execute()` (line 446), but it is NEVER passed to `crypto::encrypt_file`/`crypto::decrypt_file` (lines 470, 472) — the gt/maple branch that adds the `cancel_flag` parameter is not merged. The `draw_processing()` screen (lines 1270-1356) renders no Cancel button and even prints the text "This run cannot be force-cancelled from the GUI once it has started." (line 1351). Batch mode has a Cancel button (line 1646-1652) and checks the flag between files (line 550), so batch can abort between files but not mid-file.
- **Impact**: If a user starts encrypting a large file (e.g., a 50 GB disk image) and immediately realizes they picked the wrong file or typed the wrong password, they have no way to abort from the GUI. Their only options are to wait for the full operation to complete (which writes a `.tmp` file then renames) or to kill the app (leaving a `.tmp` partial-ciphertext file on disk). For a security tool, the inability to abort a wrong-password encryption is a real UX safety concern.
- **Verification**: Grepped `cancel_flag` in gui.rs — 9 hits, all are `store(false)` (reset), `clone()` (for batch thread), `store(true)` (batch cancel button), or `load()` (message handler). None pass it to `crypto::encrypt_file`/`decrypt_file`. Confirmed `draw_processing()` has no Cancel button (read lines 1270-1356 in full).
- **Suggested fix**: Either merge the gt/maple branch to add `cancel_flag: Option<&Arc<AtomicBool>>` to `encrypt_file`/`decrypt_file` and wire it through `execute()` + add a Cancel button to `draw_processing()`, OR add a prominent warning at the start of single-file encryption (before the save dialog) so the user can back out before the operation begins.
- **Confidence**: High

### [MEDIUM] Finding 6-2: Desktop GUI — dropping a file during Processing silently abandons the in-progress operation (which still completes and writes output)
- **Location**: gui.rs:1766-1769 (unconditional dropped_files handling in update), 309-326 (set_selected_file wipes session), 289 (set crypto_rx = None drops receiver)
- **Category**: thread-safety / ux-safety / resource-leak
- **Description**: The dropped-files handler at the top of `update()` (lines 1766-1769) runs unconditionally on every frame, regardless of `self.flow`. If the user drops a new file while `flow == AppFlow::Processing`, `set_selected_file(path)` is called, which (a) sets `self.flow = AppFlow::Configure`, (b) clears `self.password` and `self.confirm_password`, (c) sets `self.crypto_rx = None` (dropping the channel receiver), and (d) resets `self.cancel_flag` to false. The background thread spawned in `execute()` (line 459) continues running — it holds its own cloned `password` and a cloned `tx` sender. When the thread finishes, it calls `tx.try_send(GuiMsg::Done(...))` (line 482), which silently fails (receiver dropped). The thread also calls `ctx_clone.request_repaint()` (line 489), which triggers a repaint, but the message is gone. Crucially, the output file at the ORIGINAL `dest` path IS created on disk (encrypt_file writes to a `.tmp` then renames to `dest` on success).
- **Impact**: The user sees the Configure screen for the newly-dropped file with no indication that the previous encryption completed. They may later re-encrypt the original file, not realizing it was already encrypted, producing a `.vx2.vx2` double-encrypted file. The output of the abandoned operation is silently written to disk. This is a real state-machine bug.
- **Verification**: Read update() lines 1764-1770 and set_selected_file() lines 309-326. Confirmed the dropped-files check is not gated on `self.flow`. Confirmed `set_selected_file` sets `self.crypto_rx = None` (line 289 in secure_wipe_session, but set_selected_file itself doesn't null the rx — let me re-check: actually set_selected_file at line 309-326 does NOT set crypto_rx to None. Only secure_wipe_session does. So the receiver is NOT dropped by set_selected_file. But the channel is still open. The background thread sends Done/Error, which is received in the message handler. But the handler checks `self.cancel_flag` (false) and transitions to Success/Failure — overwriting the Configure state that set_selected_file just set. So the user briefly sees Configure, then the screen flips to Success/Failure for the OLD file. Confusing but not a silent completion. Let me re-verify: set_selected_file does NOT touch crypto_rx. So the receiver persists. The next update() iteration drains the channel and processes Done/Error. The flow transitions to Success/Failure for the OLD file, but self.selected_file is now the NEW file. The Success screen shows self.dest_path (the OLD dest) and self.selected_file is the NEW file — inconsistent state. The user sees a Success screen referencing the old operation while the selected_file points to the new file. Still a bug, but slightly different than described.)
- **Revised Verification**: Read set_selected_file (lines 309-326) — it does NOT clear `self.crypto_rx`. So the channel receiver persists across the dropped-file transition. The background thread's Done/Error message IS received and processed (lines 1781-1799), transitioning flow to Success/Failure. But `self.selected_file` now points to the NEW dropped file while `self.dest_path`/`self.sha256_hash` reference the OLD operation. The Success screen (draw_result) shows `self.dest_path` (old) — but if the user clicks "New file", `secure_wipe_session` clears everything. The net effect: the user drops a file during Processing, briefly sees Configure, then the screen flips to Success/Failure for the operation they thought they abandoned. Confusing but the output file is correctly written. Severity remains MEDIUM (UX confusion, potential for the user to mis-attribute the success to the new file).
- **Suggested fix**: Gate the dropped-files handler on `self.flow`: only process drops when `flow == FileDrop || flow == Configure || flow == BatchConfigure || flow == Success || flow == Failure || flow == BatchDone`. Ignore drops during `Processing`/`BatchProcessing` (or queue them for after the operation completes).
- **Confidence**: High

### [MEDIUM] Finding 6-3: Android SingleFileScreen — WIPE SOURCE FILE button deletes original with no confirmation dialog
- **Location**: SingleFileScreen.kt:506-536 (WIPE SOURCE FILE button onClick)
- **Category**: ux-safety / data-loss
- **Description**: After a successful encryption, the Success screen renders a red "WIPE SOURCE FILE" button (lines 506-536). Clicking it immediately calls `DocumentsContract.deleteDocument(context.contentResolver, inputUri!!)` (line 510-513) with NO confirmation dialog. There is no undo. The original (plaintext) file is permanently deleted from the user's storage. If the user clicked it accidentally (e.g., meant to click "DONE" which is right below it), they lose the original file. The only recovery would be from a backup or forensic file-recovery tools.
- **Impact**: Accidental permanent data loss of the original plaintext file. For a security tool that the user might operate while distracted or on a touch screen (easy misclicks), this is a real data-loss risk. The button is styled prominently (red, full-width) which increases accidental-click likelihood.
- **Verification**: Read lines 506-536. Confirmed: the onClick lambda directly calls deleteDocument with no AlertDialog or other confirmation. The button is `Button` (not `OutlinedButton`) with `containerColor = Error` (red), full-width, 50.dp height — visually prominent.
- **Suggested fix**: Wrap the deletion in an `AlertDialog` with a destructive-action confirmation: "This will permanently delete the original file. This cannot be undone. Continue?" with "Delete" (red) and "Cancel" buttons. Only call `deleteDocument` after the user confirms.
- **Confidence**: High

### [MEDIUM] Finding 6-4: Android BatchScreen — WIPE SUCCESSFUL SOURCE FILES button bulk-deletes originals with no confirmation
- **Location**: BatchScreen.kt:538-571 (WIPE SUCCESSFUL SOURCE FILES button onClick)
- **Category**: ux-safety / data-loss
- **Description**: After a batch operation completes, the Done screen renders a "WIPE SUCCESSFUL SOURCE FILES" button (lines 543-570) that iterates over all successful items and calls `DocumentsContract.deleteDocument` (line 548-551) for each, with NO confirmation dialog. A single misclick deletes ALL original files in the batch simultaneously. There is no undo, no per-file confirmation, and no rollback if some deletions succeed before one fails (the catch block at line 558 silently ignores errors and continues to the next item).
- **Impact**: Catastrophic accidental data loss — a single tap can delete dozens of original files at once. Worse than Finding 6-3 because it's bulk deletion. The `catch (e: Exception) { // ignore }` at line 558-560 means failed deletions are silently skipped, so the user can't tell which files were actually deleted vs. which survived.
- **Verification**: Read lines 538-571. Confirmed: no AlertDialog. The loop iterates `successItems` and deletes each. The catch block at line 558-560 is empty (comment says "ignore"). After the loop, `anyWiped = true` (line 562) is set unconditionally — even if all deletions failed silently, the UI shows "Source files wiped successfully." (line 580), which is misleading.
- **Suggested fix**: (1) Add a confirmation dialog listing the count of files to be deleted. (2) Track per-item deletion success and update `isWiped` only for items that were actually deleted (currently line 553/556 set `item.isWiped = true` even if the fallback `contentResolver.delete` throws — the throw is caught by the outer try at line 547, so `isWiped` is NOT set in that case; but if `deleteDocument` returns false and `contentResolver.delete` returns 0 (no rows deleted), `isWiped` IS set to true incorrectly at line 556). (3) Show a summary of how many were actually deleted vs. failed.
- **Confidence**: High

### [MEDIUM] Finding 6-5: NSIS installer and binary are not code-signed — users cannot verify authenticity; SmartScreen warns
- **Location**: installer/neuron-encrypt.nsi (entire file — no !finalize / signtool invocation); .github/workflows/release.yml:144-184 (build-installer job — no signing step)
- **Category**: supply-chain / installer
- **Description**: The NSIS installer script contains no code-signing directives (no `!finalize "signtool sign ..."`, no `SignTool` invocation). The release.yml `build-installer` job (lines 144-184) downloads the unsigned Windows binary, builds the installer with `makensis.exe`, and uploads the unsigned installer artifact. Neither the `neuron-encrypt.exe` binary nor the `NeuronEncrypt-Windows-x64-Setup.exe` installer is signed with an Authenticode certificate. Windows SmartScreen will show "Windows protected your PC" warning for the installer. Users have no way to verify the binary's authenticity or integrity against a known publisher.
- **Impact**: For a security-focused encryption tool, the lack of code-signing is a significant trust and supply-chain issue. A MITM attacker could substitute a malicious installer on a download mirror, and users would see the same SmartScreen warning for both the legitimate and malicious versions — unable to distinguish them. Users trained to click "Run anyway" past SmartScreen are especially vulnerable. Medium severity for a security tool (would be LOW for a general utility).
- **Verification**: Read neuron-encrypt.nsi in full (133 lines) — no signtool/signtool.exe/!finalize references. Read release.yml build-installer job (lines 144-184) — no signing step. The release profile in Cargo.toml has `strip = true` (line 53) which removes symbols but does NOT sign.
- **Suggested fix**: (1) Obtain an Authenticode code-signing certificate (OV or EV). (2) Add a post-build signing step in release.yml: `signtool sign /f cert.pfx /p ${{ secrets.CERT_PASSWORD }} /t http://timestamp.digicert.com neuron-encrypt.exe` and `!finalize "signtool sign ..." "0" "NeuronEncrypt-Windows-x64-Setup.exe"` in the NSIS script. (3) Publish the expected SHA-256 hashes of signed artifacts on the GitHub release page. (4) Consider a transparency log (Sigstore/rekor) for the binaries.
- **Confidence**: High

### [MEDIUM] Finding 6-6: Android MainActivity uses deprecated untyped `getParcelableExtra<Uri>` — potential type-confusion crash from attacker-controlled intent
- **Location**: MainActivity.kt:96 (`intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)`)
- **Category**: android-lifecycle / error-handling
- **Description**: `getParcelableExtra<Uri>(Intent.EXTRA_STREAM)` uses the deprecated reified-inline form that performs an unchecked cast. On Android API 33+ (Android 13+), this method is deprecated in favor of the type-safe `getParcelableExtra(String, Class<T>)` overload. The deprecated form does an unchecked cast internally; if an attacker app sends an `ACTION_SEND` intent with `EXTRA_STREAM` set to a Parcelable that is NOT a `Uri` (e.g., a custom Parcelable or a `Rect`), the unchecked cast can cause a `ClassCastException` at the point of access, crashing the app. Since `MainActivity` is `android:exported="true"` (AndroidManifest.xml:13), any third-party app can send intents to it.
- **Impact**: A malicious app could crash Neuron Encrypt by sending a crafted `ACTION_SEND` intent with a non-Uri Parcelable in `EXTRA_STREAM`. This is a denial-of-service vector. The crash occurs before any encryption logic runs, so no data is corrupted — but the app force-closes, which is a poor user experience and could be chained with other issues. On older Android versions (< 33), the unchecked cast is less likely to crash but still technically unsafe.
- **Verification**: Read MainActivity.kt line 96. Confirmed: `intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)` — no `Class` argument. The Android lint flags this as a deprecation warning on API 33+. The Activity is exported (AndroidManifest.xml:13) with an `ACTION_SEND` intent filter (line 24).
- **Suggested fix**: Replace with the type-safe overload: `intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)` (requires API 33+; for backward compatibility, use `if (Build.VERSION.SDK_INT >= 33) ... else @Suppress("DEPRECATION") intent.getParcelableExtra(...)`. Also wrap in a try-catch for `ClassCastException` to defensively handle malformed intents.
- **Confidence**: High

### [MEDIUM] Finding 6-7: JNI fd leak — if `convert_byte_array` or `new_global_ref` fails after Kotlin `detachFd`, the fds are leaked
- **Location**: android/neuron-encrypt-jni/src/lib.rs:151-181 (native_encrypt_impl), 227-257 (native_decrypt_impl); CryptoService.kt:27-28, 58-59 (detachFd before JNI call)
- **Category**: resource-leak / unsafe-rust
- **Description**: In CryptoService.kt, `input.detachFd()` and `output.detachFd()` (lines 27-28, 58-59) are called BEFORE `NeuronEncryptNative.nativeEncrypt(...)`. `detachFd()` transfers fd ownership from the `ParcelFileDescriptor` to the caller — after this, the PFD's `use`-block close is a no-op. The JNI side is expected to wrap the fds in `File::from_raw_fd` (which takes ownership and closes on drop). However, in `native_encrypt_impl` (lines 151-181), several operations can fail BEFORE `File::from_raw_fd` wraps the fds (line 180-181): the `input_fd < 0` check (line 151 — but this is before detachFd on the Kotlin side, so OK), `env.get_java_vm()` (line 155), `env.new_global_ref(cancel_flag)` (line 160), `env.new_global_ref(progress_listener)` (line 167), and `env.convert_byte_array(password)` (line 174). If any of these fail, `fail_with_exception` is called and the function returns without wrapping the fds — the fds are leaked (neither the Kotlin PFD nor the Rust `File` owns them).
- **Impact**: File descriptor leak. Each failed call leaks 2 fds. On Android, the per-process fd limit is typically 1024. After ~512 failed operations, the app would hit "Too many open files" and start failing all file operations. The failure paths are rare (JVM OOM, invalid JObject references), but in a long-running session with repeated errors (e.g., a malformed password ByteArray), the leak could accumulate. The same issue exists in `native_decrypt_impl` (lines 227-257).
- **Verification**: Read CryptoService.kt lines 20-34 (detachFd inside use-block, before nativeEncrypt). Read native_encrypt_impl lines 151-181 — confirmed `File::from_raw_fd` is at line 180-181, AFTER all the fallible JNI calls. The `fail_with_exception` returns at lines 152, 157, 163, 170, 176 do NOT close the fds.
- **Suggested fix**: Restructure so that `File::from_raw_fd` wraps the fds FIRST (before any fallible JNI calls), or have `fail_with_exception` close the fds before returning. Simplest fix: move the `from_raw_fd` calls to immediately after the `input_fd < 0` check (line 151), then proceed with the fallible JNI operations — if they fail, the `File` locals will be dropped (closing the fds) when the function returns. Alternative: pass the fds as `jint` and have the JNI always wrap them in `File` at the top, then do the fallible work.
- **Confidence**: High

### [MEDIUM] Finding 6-8: CLI `--password-file` with invalid UTF-8 leaks password bytes — `Vec<u8>` dropped without zeroize
- **Location**: cli.rs:109-120 (read_password), specifically line 114-116 (`String::from_utf8(bytes).map_err(...)`)
- **Category**: error-handling / memory-hygiene
- **Description**: `read_password` reads the password file via `fs::read(path)` which returns a `Vec<u8>` (line 111). This `Vec<u8>` holds the raw password bytes but is NOT wrapped in `Zeroizing`. It is then passed to `String::from_utf8(bytes)` (line 114), which takes ownership of the `Vec`. If `from_utf8` succeeds, the buffer is now owned by the `String` (which is then wrapped in `Zeroizing` — good). But if `from_utf8` FAILS (the password file contains invalid UTF-8 bytes), it returns a `FromUtf8Error` which owns the original `Vec<u8>`. The `map_err` at line 115 converts this to a tuple `(ExitCode, String)` — the `FromUtf8Error` is dropped, and with it the `Vec<u8>` containing the password bytes is dropped via the standard `Drop for Vec`, which does NOT zeroize the memory. The freed heap memory may be reallocated later, and the password bytes could be read by another allocation until the memory is overwritten.
- **Impact**: If a user points `--password-file` at a file that happens to contain invalid UTF-8 (e.g., a binary key file, a file with a BOM or encoding mismatch, or a file with a stray non-UTF-8 byte), the password bytes are leaked into freed heap memory without zeroization. The probability depends on how often users hit this error path, but for a security tool that explicitly supports `--password-file` for CI/CD, users may intentionally use binary key files. Low-to-medium severity.
- **Verification**: Read cli.rs lines 109-120. Confirmed: `fs::read(path)` returns `Vec<u8>` (not `Zeroizing<Vec<u8>>`). `String::from_utf8(bytes)` consumes the Vec. On error, `FromUtf8Error::into_bytes()` would give back the Vec, but the code uses `map_err` which drops the error. The Vec's Drop runs without zeroize. Confirmed there is no `Zeroizing` wrapper around `bytes`.
- **Suggested fix**: Wrap the bytes in `Zeroizing` from the start: `let bytes = Zeroizing::new(fs::read(path).map_err(...)?);` then use `String::from_utf8(bytes.to_vec())` — but that copies. Better: use `String::from_utf8(Zeroizing::new(bytes).as_mut().to_vec())` — still copies. Best fix: change `read_password` to return `Zeroizing<Vec<u8>>` instead of `Zeroizing<String>`, and pass `&[u8]` to `password.as_bytes()` callers. This avoids the UTF-8 round-trip entirely and supports binary passwords. The crypto layer already takes `&[u8]` for the password, so no crypto change needed.
- **Confidence**: High

### [MEDIUM] Finding 6-9: Desktop GUI batch mode lacks the re-encrypt safety check that single-file mode has
- **Location**: gui.rs:496-611 (execute_batch — no is_vx2_file re-encrypt check), 1167-1192 (single-file re-encrypt checkbox that batch lacks), 613-632 (pick_multiple_files — mixed files default to Encrypt)
- **Category**: ux-safety / error-handling
- **Description**: Single-file mode has a re-encrypt safety check: if the selected file is already a `.vx2` file and the user chooses Encrypt, a checkbox "I understand this will encrypt a file that is already encrypted." must be ticked before the ENCRYPT button is enabled (lines 1167-1192, gated at line 1214-1219). Batch mode has NO equivalent check. In `pick_multiple_files` (lines 613-632), if the selected files are a MIX of `.vx2` and non-`.vx2` files, the mode defaults to `Mode::Encrypt` (line 623). `execute_batch` (lines 496-611) iterates all files and encrypts each one without checking `is_vx2_file`. So `.vx2` files in a mixed batch get double-encrypted (producing `.vx2.vx2`), silently.
- **Impact**: A user selecting a mixed batch (e.g., 5 plaintext files + 2 already-encrypted `.vx2` files) and clicking "Encrypt All Files" will silently double-encrypt the 2 `.vx2` files, producing `.vx2.vx2` outputs. The user may not notice (the success screen just shows per-file success). Later, they may try to decrypt the `.vx2.vx2` file, which will fail (it's encrypted twice, so decrypting once yields a `.vx2` file, not the plaintext). This is a real UX confusion vector with potential data-accessibility loss.
- **Verification**: Read execute_batch (lines 496-611) — confirmed no `is_vx2_file` check. Read pick_multiple_files (lines 613-632) — confirmed mixed files default to Encrypt. Read draw_batch_configure (lines 1495-1585) — confirmed no re-encrypt warning/checkbox. Contrast with draw_configure (lines 1167-1192) which has the checkbox for single-file mode.
- **Suggested fix**: In `pick_multiple_files`, if any file is `.vx2` and the mode would be Encrypt, show a warning in `draw_batch_configure` and require a checkbox (similar to single-file mode). Alternatively, auto-skip `.vx2` files in batch encrypt mode (with a per-file "skipped" status) or auto-route them to decrypt.
- **Confidence**: High

### [LOW] Finding 6-10: JNI `catch_unwind` is dead code in release builds — `panic = "abort"` means panics never unwind
- **Location**: android/neuron-encrypt-jni/Cargo.toml:20 (`panic = "abort"`); lib.rs:305-325, 338-358 (`panic::catch_unwind(AssertUnwindSafe(...))`)
- **Category**: unsafe-rust / error-handling
- **Description**: The JNI Cargo.toml sets `panic = "abort"` in the release profile (line 20). With `panic = "abort"`, any panic immediately aborts the process via `abort()` — there is no unwinding. The `panic::catch_unwind(AssertUnwindSafe(|| { ... }))` wrappers in `Java_com_neuronencrypt_app_NeuronEncryptNative_nativeEncrypt` (line 305) and `nativeDecrypt` (line 338) rely on unwinding to catch panics. In a release build (the only build shipped to Android), `catch_unwind` cannot catch a panic — a panic inside the closure will abort the process before the `match res` at line 317/350 ever runs. The `Err(_)` branch (lines 319-324, 352-357) that calls `zero_java_array` and `throw_new` is unreachable in release. The safety net only exists in debug builds.
- **Impact**: If a panic occurs in the native code (e.g., OOM allocating the 1MB buffer in encrypt_stream, an index-out-of-bounds, an unwrap on None), the entire Android app crashes immediately with no exception thrown to Kotlin. The user sees a "Neuron Encrypt keeps stopping" dialog. The `zero_java_array` cleanup in the catch branch never runs, so the password ByteArray is NOT zeroed on panic. However, since the process is aborting, the OS will reclaim all memory — so the password-zeroization gap is moot (the memory is freed by the OS). The real impact is that the panic-safety design is misleading: the code looks like it handles panics gracefully, but it doesn't in release.
- **Verification**: Read Cargo.toml line 20 (`panic = "abort"`). Read lib.rs lines 305-325 and 338-358. Confirmed `catch_unwind` is used. The Rust docs state: "If the panic strategy is set to abort, ... `catch_unwind` has no effect" — panics abort instead of unwinding.
- **Suggested fix**: Either (a) remove `panic = "abort"` from the JNI release profile (accept the small binary-size and runtime cost of unwinding tables, but gain the catch_unwind safety net), or (b) keep `panic = "abort"` and remove the `catch_unwind` wrappers (and document that panics abort the process). Option (a) is recommended for a JNI library where graceful degradation (throwing a Java exception instead of crashing) is preferable to aborting the app. Note: the core `neuron-encrypt` crate also uses `panic = "abort"` (Cargo.toml:54), so even if the JNI crate allowed unwinding, panics inside the core crypto functions would still abort — the fix would need to be applied to both crates.
- **Confidence**: High

### [LOW] Finding 6-11: JNI `map_error` uses string comparison on `io::Error` Display output — fragile cancellation detection
- **Location**: android/neuron-encrypt-jni/src/lib.rs:88-92 (`map_error`), 19 (`CANCELLED_IO_MESSAGE = "operation cancelled"`)
- **Category**: error-handling
- **Description**: `map_error` detects cancellation by matching `CryptoError::Io(ref io_err) if io_err.to_string() == CANCELLED_IO_MESSAGE` (line 90). `CANCELLED_IO_MESSAGE` is the string `"operation cancelled"` (line 19). The `CancelableReader` (lines 41-49, 52-62) creates an `io::Error` with `io::Error::new(io::ErrorKind::Other, CANCELLED_IO_MESSAGE)` — so the Display output of the error is exactly `"operation cancelled"`. The string comparison works today. But it is fragile: if the `io::Error` Display format ever changes (e.g., a future Rust version adds a prefix like "other error: "), or if a different error path produces an `io::Error` with the same message, the comparison breaks. The cancellation would be misreported as "Storage I/O failed." (line 109) instead of "Cancelled".
- **Impact**: If the string comparison fails, a user-initiated cancel would be reported as a generic I/O error instead of "Cancelled". The Kotlin side would show "Storage I/O failed." and the user wouldn't know their cancel was honored. No security impact, but confusing UX. The risk is low because the message is hardcoded in the same crate and `io::Error::new(kind, &str)` Display is stable, but the pattern is an anti-pattern (string-based dispatch).
- **Verification**: Read lib.rs lines 19, 41-49, 88-92. Confirmed: `CANCELLED_IO_MESSAGE` is a `&str`, `io::Error::new(ErrorKind::Other, CANCELLED_IO_MESSAGE)` creates the error, and `io_err.to_string() == CANCELLED_IO_MESSAGE` compares Display output. The `to_string()` of an `io::Error` created with `Error::new(kind, msg)` where `msg: &str` returns the `&str` unchanged (no prefix) — confirmed by the std source. So it works today, but it's fragile.
- **Suggested fix**: Use a custom `io::Error` subclass or a sentinel `io::ErrorKind`. Better: define a custom error type `struct Cancelled;` and use `io::Error::new(io::ErrorKind::Interrupted, Cancelled)`, then in `map_error` downcast via `io_err.get_ref().and_then(|e| e.downcast_ref::<Cancelled>()).is_some()`. Or use `io::ErrorKind::Interrupted` directly (semantically correct for cancellation) and match on `io_err.kind()` instead of the string.
- **Confidence**: High

### [LOW] Finding 6-12: GUI displays SHA-256 hash of plaintext in success screen — leak if screenshot shared
- **Location**: gui.rs:463-467 (compute_sha256 of plaintext BEFORE encryption), 477-481 (hash of decrypted output), 1413-1430 (hash displayed in draw_result), 559 (CLI also prints "SHA-256 (original)" to stderr)
- **Category**: information-disclosure / ux-safety
- **Description**: In `execute()` (line 463-467), the GUI computes `compute_sha256(&file_path)` of the ORIGINAL plaintext file BEFORE calling `encrypt_file`. This hash is stored in `self.sha256_hash` and displayed in the Success screen (lines 1413-1430) as a truncated hex string. The CLI similarly prints "SHA-256 (original): {h}" to stderr (line 559) for encrypt mode. The hash is of the PLAINTEXT, not the ciphertext.
- **Impact**: If the user takes a screenshot of the Success screen (e.g., to share on social media or in a support ticket), the truncated SHA-256 of the plaintext is visible. An attacker with the screenshot and a candidate plaintext (e.g., a known file they suspect the user encrypted) can compute the candidate's SHA-256 and compare the first 24 + last 24 hex chars (48 of 64 chars shown) to confirm or rule out their guess. This is a minor information leak — the hash doesn't reveal the plaintext, but it allows verification of a guess. For most users this is negligible; for high-security scenarios (e.g., a journalist encrypting a known leaked document), it could be a concern. The CLI's stderr output is also captured by shell redirects or process monitors.
- **Verification**: Read gui.rs lines 463-467 (hash_source = compute_sha256(&file_path) for encrypt mode). Read lines 1413-1430 (hash_display shows first 24 + last 24 hex chars). Read cli.rs line 559 (`eprintln!("SHA-256 (original): {h}")`). Confirmed: the hash is of the plaintext for encrypt mode.
- **Suggested fix**: Make the hash display opt-in (a "Show hash" toggle in the Success screen, hidden by default). Or hash the CIPHERTEXT instead of the plaintext (less useful for verification, but no leak). Or remove the hash display entirely from the GUI (the CLI can keep it for scripting). At minimum, document that the hash is of the original plaintext so users understand the sensitivity.
- **Confidence**: High

### [LOW] Finding 6-13: `std::env::set_var("RUST_BACKTRACE", "1")` is deprecated in Rust 1.85+ for edition 2024 — future-proofing concern
- **Location**: main.rs:39-40 (`#[cfg(debug_assertions)] std::env::set_var("RUST_BACKTRACE", "1");`); Cargo.toml:4 (`edition = "2021"`)
- **Category**: code-quality / future-proofing
- **Description**: `std::env::set_var` was made `unsafe fn` in Rust 1.85 for edition 2024 (due to data-race concerns with multi-threaded env access). For edition 2021, it remains safe but emits a deprecation warning (`unsafe_set_var` lint, allow-by-default in 1.85, deny-by-default in future editions). The CI uses Rust 1.88 (release.yml:25, android.yml uses stable). The crate is edition 2021, so the call compiles today. But if the crate is upgraded to edition 2024 (or if clippy tightens the lint), this line would fail the build. The CI runs `cargo clippy --all-targets -- -D warnings` (release.yml:100), which would fail if the lint is warn-by-default.
- **Impact**: No current impact (edition 2021, set_var is safe). Future impact: when the crate upgrades to edition 2024, this line becomes a compile error. If clippy's `unsafe_set_var` lint is promoted to warn-by-default before then, the CI would break.
- **Verification**: Read main.rs lines 39-40. Confirmed: `std::env::set_var` without `unsafe`. Cargo.toml line 4: `edition = "2021"`. The CI uses Rust 1.88 (release.yml:25).
- **Suggested fix**: Wrap in `unsafe` now (with a SAFETY comment) to future-proof, OR set `RUST_BACKTRACE` via the `RUSTFLAGS` env var in the CI/build script instead of at runtime, OR use `std::panic::set_hook` to print backtraces without env-var manipulation. The simplest fix: `// SAFETY: single-threaded before eframe::run_native, no data race. unsafe { std::env::set_var("RUST_BACKTRACE", "1"); }`.
- **Confidence**: Medium (the deprecation timeline is certain; the exact Rust version that promotes the lint to deny is less certain)

### [LOW] Finding 6-14: Android `persistUriPermission` accumulates persistable URI permissions without release — ~128 limit
- **Location**: SingleFileScreen.kt:622-630 (persistUriPermission), 81 (called in selectFile); BatchScreen.kt:83, 100-104 (called for each selected file and the tree URI)
- **Category**: resource-leak / android-lifecycle
- **Description**: `persistUriPermission` calls `context.contentResolver.takePersistableUriPermission(uri, flags)` (line 624). Persisted URI permissions survive across app sessions and are never released by the app. Android limits the number of persistable URI permissions per app to ~128 (the exact limit is `MAX_PERSISTED_URI_PERMISSIONS` in the framework, typically 128-512 depending on Android version). Each time the user selects a new file (SingleFileScreen) or a batch of files (BatchScreen), a new persistable permission is taken. Over many sessions, the app accumulates permissions for URIs the user no longer cares about. Once the limit is hit, `takePersistableUriPermission` throws (caught by the catch blocks at lines 625-629, so no crash, but the URI won't be persistable — meaning the app can't access it after a process restart).
- **Impact**: After ~128 file selections (across the app's lifetime), new selections won't get persistable permissions. If the user closes and reopens the app, the most recently selected files would be inaccessible (the permission wasn't persisted). The user would have to re-select the file each time. No security impact, but a resource-leak / UX degradation. Low severity for typical usage (most users won't hit 128), but high for power users doing batch operations over time.
- **Verification**: Read persistUriPermission (lines 622-630) — calls `takePersistableUriPermission` with no corresponding `releasePersistableUriPermission`. Grepped for `releasePersistableUriPermission` — no matches in the codebase. Confirmed: permissions are never released.
- **Suggested fix**: (1) Call `context.contentResolver.releasePersistableUriPermission(uri, flags)` when the user is done with a file (e.g., on "DONE" click, or when a new file is selected replacing the old one). (2) For batch mode, release permissions after the batch completes. (3) Periodically prune old persisted permissions via `contentResolver.persistedUriPermissions` (API 19+) and releasing the oldest ones beyond a threshold (e.g., keep the 32 most recent).
- **Confidence**: High

### [LOW] Finding 6-15: CLI `NEURON_PASSWORD` env var is visible to child processes and `/proc/PID/environ` — documented but inherent leak
- **Location**: cli.rs:122-130 (read NEURON_PASSWORD env var); after_help examples at line 41 (`NEURON_PASSWORD="mypass" neuron-encrypt-cli encrypt -i secret.pdf`)
- **Category**: information-disclosure / supply-chain
- **Description**: `read_password` checks `std::env::var("NEURON_PASSWORD")` (line 122) as a fallback for non-interactive password input. Environment variables are visible to: (a) child processes spawned by the CLI (via inherited env), (b) any process on Linux via `/proc/PID/environ` (same-user or root), (c) process-monitoring tools (`ps`, `htop` with env display), (d) shell history (if set inline like `NEURON_PASSWORD="mypass" neuron-encrypt-cli ...`). The code prints a warning (lines 123-128) recommending `--password-file` instead, which is good. But the env-var path remains as a supported feature.
- **Impact**: The password is exposed in multiple ways. On a multi-user system, another user with the same UID (or root) can read `/proc/PID/environ` to steal the password. On a single-user system, any background process or shell helper can read the env. Shell history (if the user types `NEURON_PASSWORD=...`) persists the password in plaintext in `~/.bash_history` or `~/.zsh_history`. The warning mitigates but doesn't prevent misuse. Low severity (documented, warned, user opt-in).
- **Verification**: Read cli.rs lines 122-130. Confirmed: `std::env::var("NEURON_PASSWORD")` is read and returned as `Zeroizing::new(pw)`. The warning at lines 123-128 is printed to stderr. The `after_help` at line 41 documents this usage.
- **Suggested fix**: The warning is good. Consider: (a) deprecating `NEURON_PASSWORD` in a future release (print a stronger deprecation warning), (b) adding a `--password-fd` option to read the password from a file descriptor (more secure than env, less cumbersome than `--password-file` for some setups), (c) on Linux, use `prctl(PR_SET_PDEATHSIG)` or `clearenv` after reading to scrub the env from the process (doesn't help with `/proc/PID/environ` of the current process, but prevents child inheritance).
- **Confidence**: High

### [LOW] Finding 6-16: Closing the GUI mid-encryption leaves a `.tmp` partial-ciphertext file on disk with no cleanup
- **Location**: gui.rs:459-490 (std::thread::spawn — daemon-like, no join on app exit); crypto.rs:301-309 (`tmp_path` creates `dest.{16hex}.tmp`)
- **Category**: resource-leak
- **Description**: When the user closes the egui window during a `Processing` operation, `eframe::run_native` returns, `main()` returns, and the process exits. The background `std::thread::spawn` thread (line 459) is killed mid-operation (it's not joined). At the moment of death, `encrypt_file` may have written a partial `.tmp` file (e.g., `secret.pdf.abc123.tmp`) containing partial V3 ciphertext (useless to an attacker without the key, but occupying disk space). The final `dest` file (e.g., `secret.pdf.vx2`) is NOT created (the rename from `.tmp` to `dest` only happens on success). On the next app launch, no cleanup runs — the `.tmp` file persists indefinitely. Repeated aborts accumulate `.tmp` files.
- **Impact**: Disk-space leak. Each aborted encryption leaves a `.tmp` file the size of the partial encryption (up to the full file size if aborted near the end). For a user who frequently cancels large encryptions, this could waste gigabytes. The `.tmp` files contain partial ciphertext (no plaintext leak — the V3 format encrypts chunks in-place, so the `.tmp` has encrypted chunks + a header, but no final tag, so it can't be decrypted). No security impact, just hygiene.
- **Verification**: Read gui.rs line 459 (`std::thread::spawn(move || {...})`) — no `JoinHandle` stored, no join on exit. Read crypto.rs `tmp_path` (lines 301-309) and `encrypt_file` (lines 395-511) — confirmed the `.tmp` file is created and only renamed to `dest` on success (line 510). If the process is killed before line 510, the `.tmp` persists. Confirmed no cleanup-on-startup logic exists in gui.rs or main.rs.
- **Suggested fix**: On app startup (in `NeuronEncryptApp::new` or `main`), scan common directories for `*.tmp` files matching the `tmp_path` pattern and offer to clean them up. Alternatively, register a `ctrlc` handler that waits for the background thread to finish before exiting. The simplest fix: on startup, walk the user's recent directories and delete `*.tmp` files older than 1 day (low risk of deleting in-progress files from another instance, since only one instance is expected).
- **Confidence**: High

### [LOW] Finding 6-17: Desktop GUI — `rfd::FileDialog::save_file()` and `pick_file()` block the GUI thread on Windows
- **Location**: gui.rs:329 (`rfd::FileDialog::new().pick_file()`), 432-438 (`rfd::FileDialog::new()...save_file()`)
- **Category**: ux-safety / thread-safety
- **Description**: `rfd::FileDialog::pick_file()` (line 329) and `save_file()` (line 435) are the SYNCHRONOUS APIs. On Windows, these block the calling thread (the egui GUI thread) until the user closes the dialog. While the dialog is open, the egui render loop is paused — no `update()` calls fire, no repaints happen. If a background crypto thread is running and sending progress messages via the channel, those messages queue up but aren't drained until the dialog closes. On Linux, rfd uses the async GTK backend, but the synchronous API still blocks (it runs a nested event loop). On macOS, it blocks similarly to Windows.
- **Impact**: If the user opens a file/save dialog during a `Processing` operation (which shouldn't happen normally, since the Processing screen doesn't have a file-pick button — but the dropped-files handler at line 1766 could trigger `set_selected_file` which doesn't open a dialog, so this specific case is OK). The more realistic scenario: the user clicks "Browse file" or the save dialog is open while a previous operation's background thread finishes — the Done message queues, and the GUI appears frozen (spinner doesn't animate) until the dialog closes. On Windows, the window may show "(Not Responding)" if the dialog is open for >5 seconds. Low severity (the dialog usually closes quickly), but noticeable for network-mounted drives where the dialog may hang.
- **Verification**: Read gui.rs line 329 (`pick_file` — synchronous) and line 432-438 (`save_file` — synchronous). rfd 0.15 docs: `pick_file()` and `save_file()` are blocking; `pick_file_async()` and `save_file_async()` are the async alternatives. Confirmed: the code uses the synchronous variants.
- **Suggested fix**: Use rfd's async APIs (`AsyncFileDialog`) with a tokio/async-std runtime, or spawn the dialog on a background thread and send the result back via a channel. For egui, the idiomatic approach is `rfd::AsyncFileDialog::new().pick_file().then(move |result| { ... })` with the egui context cloned for `request_repaint()`. This is a larger refactor; for now, document that the GUI may briefly freeze during file dialogs.
- **Confidence**: Medium (the blocking behavior is certain; the impact depends on the user's filesystem and dialog duration)

### [LOW] Finding 6-18: NSIS installer does not verify binary checksum before install — tampered binary would be installed
- **Location**: installer/neuron-encrypt.nsi:77 (`File "..\neuron-encrypt\target\x86_64-pc-windows-msvc\release\neuron-encrypt.exe"` — no checksum); .github/workflows/release.yml:157-161 (Prepare installer input — copies downloaded artifact without checksum verification)
- **Category**: supply-chain / installer
- **Description**: The NSIS installer's `Section "Core Application"` (line 71-95) uses `File` (line 77) to copy the pre-built `neuron-encrypt.exe` into the install directory. NSIS's `File` command does not verify a checksum — it copies whatever bytes are at the source path. In the CI `build-installer` job (release.yml:157-161), the Windows binary is downloaded from the `build` job's artifact (`download-artifact@v4`), then `cp`'d into the expected path. Neither the download nor the install verifies a SHA-256 hash. If the artifact is tampered with between the `build` job and the `build-installer` job (e.g., via a compromised runner, a MITM on the artifact storage, or a malicious PR that modifies the binary), the installer would package and install the tampered binary without detection.
- **Impact**: A tampered binary could be installed silently. The user has no way to verify the installed binary matches the intended build. Combined with Finding 6-5 (no code signing), this means there are TWO missing integrity checks: (1) the installer doesn't verify the binary's hash, and (2) the binary/installer isn't signed. An attacker who can inject a tampered binary into the CI artifact stream can ship malware. Low-to-medium severity (mitigated by GitHub Actions' artifact integrity, but defense-in-depth is missing).
- **Verification**: Read neuron-encrypt.nsi line 77 — confirmed `File` with no checksum directive. Read release.yml lines 157-161 — confirmed `cp NeuronEncrypt-Windows.exe neuron-encrypt/target/.../neuron-encrypt.exe` with no `sha256sum` check. NSIS does not have a built-in `File` checksum feature, but plugins like `FCSC` or a custom `nsExec::Exec 'certutil -hashfile ...'` could verify.
- **Suggested fix**: (1) In the CI `build` job, compute `sha256sum` of the binary and upload it as a separate artifact (or embed it in the installer build). (2) In the `build-installer` job, after downloading the binary, verify its SHA-256 against the expected value before packaging: `echo "$EXPECTED_SHA256  neuron-encrypt.exe" | sha256sum -c`. (3) In the NSIS script, optionally verify the binary's checksum during install using `nsExec::Exec 'certutil -hashfile "$INSTDIR\neuron-encrypt.exe" SHA256'` and compare against a hardcoded value baked into the installer at build time.
- **Confidence**: High

### [LOW] Finding 6-19: Android CI workflow does not run clippy, fmt, or tests on the JNI crate
- **Location**: .github/workflows/android.yml:50-55 (Build Rust JNI Libraries — only builds, no clippy/test); compare to .github/workflows/release.yml:95-112 (desktop CI runs fmt --check, clippy -D warnings, cargo test --all)
- **Category**: supply-chain / code-quality
- **Description**: The Android CI workflow (android.yml) runs `./android/build-rust.sh` (line 55) which builds the JNI library for 4 Android targets. It does NOT run `cargo clippy`, `cargo fmt --check`, or `cargo test` on the JNI crate. The desktop release workflow (release.yml:95-112) runs all three on the `neuron-encrypt` crate. So the JNI crate (which contains `unsafe` blocks, FFI, and panic-handling logic) gets no static-analysis or test coverage in CI. The `cargo audit` and `cargo deny` in release.yml (lines 42-48) run in the `neuron-encrypt` working directory, so they don't cover the JNI crate's dependencies (jni, zeroize) either.
- **Impact**: Lint regressions and bugs in the JNI crate (e.g., a new `unwrap()` added to an unsafe block, a misuse of `GlobalRef`, an FFI signature mismatch) would not be caught by CI. The JNI crate is the security-critical boundary between Java and Rust — undetected bugs here could cause crashes, memory unsafety, or fd leaks (like Finding 6-7). Low-to-medium severity (the crate is small at 358 lines, but it's all unsafe FFI).
- **Verification**: Read android.yml lines 50-55 — confirmed only `./android/build-rust.sh` runs, no clippy/fmt/test. Read release.yml lines 95-112 — confirmed desktop CI runs fmt, clippy, test, check. The JNI Cargo.toml has no `[lints]` section and no test targets.
- **Suggested fix**: Add a `cargo clippy --all-targets -- -D warnings` step (and `cargo fmt --check`) to android.yml for the JNI crate, cross-compiled to one Android target (e.g., `aarch64-linux-android`) for fast feedback. Also run `cargo audit` and `cargo deny check` in the `android/neuron-encrypt-jni` directory. Consider adding unit tests for the pure-Rust helpers (e.g., `map_error`, `zero_java_array` logic) that don't require a JVM.
- **Confidence**: High

### [INFO] Finding 6-20: JNI `Arc<JavaVM>` is redundant — `JavaVM` is internally `Arc`-like
- **Location**: android/neuron-encrypt-jni/src/lib.rs:155-158 (`env.get_java_vm()` returns `JavaVM`), 183 (`let vm = Arc::new(vm);`), 187/192 (`Arc::clone(&vm)`)
- **Category**: code-quality
- **Description**: `env.get_java_vm()` (line 155) returns a `JavaVM` which, in the `jni` crate, is already a cheaply-clonable handle (internally it wraps a raw `*mut JavaVM` with no lifetime — cloning it just copies the pointer). The code wraps it in `Arc::new(vm)` (line 183) and then `Arc::clone(&vm)` (lines 187, 192) to share it between `CancelableReader` and `JniReporter`. This double-indirection (Arc around an already-cloneable handle) is redundant — it adds an atomic refcount increment/decrement on each clone/drop for no benefit.
- **Impact**: None functionally. Minor: one extra heap allocation (the Arc) per JNI call, and atomic operations on clone/drop. Negligible perf impact (the JNI call itself is far more expensive). Code-quality: the Arc suggests `JavaVM` is NOT cheaply cloneable, which is misleading to readers.
- **Verification**: Read lib.rs lines 155-193. The `jni` crate's `JavaVM` type (jni 0.21) implements `Clone` and is documented as "a cheaply cloneable handle". Confirmed: the Arc wrap is redundant.
- **Suggested fix**: Remove the `Arc::new(vm)` and just clone the `JavaVM` directly: `let vm = env.get_java_vm()?; let reader_vm = vm.clone(); let reporter_vm = vm.clone();`. Update `CancelableReader` and `JniReporter` to hold `JavaVM` instead of `Arc<JavaVM>`.
- **Confidence**: High

### [INFO] Finding 6-21: JNI cancel-check performs a JNI upcall on every 1MB chunk read — minor perf cost
- **Location**: android/neuron-encrypt-jni/src/lib.rs:28-37 (`is_cancelled` calls `env.call_method`), 40-50 (`Read::read` calls `is_cancelled` on every read)
- **Category**: code-quality / performance
- **Description**: `CancelableReader::read` (line 41-49) calls `self.is_cancelled()` (line 42) at the start of every `read` call. `is_cancelled` (lines 28-37) does: `self.vm.attach_current_thread()` (cheap if already attached, but still a function call), then `env.call_method(&self.cancel, "get", "()Z", &[])` — a full JNI upcall to invoke `AtomicBoolean.get()` on the Java side. The crypto layer calls `read` once per 1MB chunk. For a 1GB file, that's ~1024 JNI upcalls just for cancel-checking. Each upcall is ~1-10μs, so ~1-10ms total — negligible compared to the ~seconds-long Argon2id KDF.
- **Impact**: Negligible. The cancel-check latency is dwarfed by the I/O and crypto latency. Not a real performance issue. However, it IS a design smell: the cancel check could be throttled (e.g., only check every 16ms or every 4 chunks) to reduce JNI overhead, but the current per-chunk approach gives sub-second cancel latency which is good UX.
- **Verification**: Read lib.rs lines 28-50. Confirmed: `is_cancelled` is called on every `read`. The crypto `CHUNK_SIZE` is 1MB (per Task 5's crypto.rs analysis), so for a 1GB file, ~1024 reads = ~1024 upcalls.
- **Suggested fix**: None required. Optional: throttle the cancel check to once every 16ms (using `Instant::now()` to track the last check time) to reduce upcall overhead on very large files. The trade-off is slightly worse cancel latency (up to 16ms vs. immediate). Not worth the complexity for the current per-chunk approach.
- **Confidence**: High

### [INFO] Finding 6-22: AndroidManifest missing `android:allowBackup="false"` — app has no persistent state so low impact
- **Location**: AndroidManifest.xml:4-9 (`<application>` element — no `android:allowBackup` attribute)
- **Category**: android-lifecycle / information-disclosure
- **Description**: The `<application>` element (lines 4-9) does not set `android:allowBackup`. The default is `true`, which means Android's Auto Backup may attempt to back up app data to Google Drive. However, the app has no persistent state: no SQLite databases, no SharedPreferences, no files in `filesDir`/`cacheDir` (all file operations use SAF ContentResolver URIs, which are not backed up). So the backup would be empty. The only thing that COULD be backed up is the persisted URI permissions (if Android backs those up — it does not, by design). So the practical impact is nil.
- **Impact**: None. The backup is empty because the app stores no local state. However, for a security tool, setting `allowBackup="false"` is best practice — it prevents any future feature (e.g., a SharedPreferences-based settings panel) from inadvertently being backed up. It also signals to security-conscious users that the app doesn't participate in cloud backup.
- **Verification**: Read AndroidManifest.xml lines 4-9. Confirmed: no `android:allowBackup` attribute. Grepped the Kotlin code for SharedPreferences, SQLite, and file I/O — all file access is via ContentResolver (SAF), no local storage.
- **Suggested fix**: Add `android:allowBackup="false"` and `android:fullBackupContent="false"` to the `<application>` element. This is a one-line change with no downside.
- **Confidence**: High

### [INFO] Finding 6-23: AndroidManifest intent-filter accepts broad `application/octet-stream` MIME — app becomes default handler for many file types
- **Location**: AndroidManifest.xml:22-28 (intent-filter with `<data android:mimeType="application/octet-stream" />`)
- **Category**: android-lifecycle / ux-safety
- **Description**: The intent-filter on MainActivity (lines 22-28) declares `ACTION_VIEW` and `ACTION_SEND` for `application/octet-stream` MIME type and `.*\\.vx2` path pattern. `application/octet-stream` is a generic binary MIME type used by web servers for arbitrary binary downloads. By registering for it, Neuron Encrypt becomes a candidate handler for ANY binary file the user downloads or receives (e.g., a `.bin` firmware file, a `.dat` data file, an unknown extension). When the user taps "Open" on such a download, Android may offer Neuron Encrypt as the default app. If the user selects "Always", all future octet-stream downloads open in Neuron Encrypt.
- **Impact**: UX annoyance — the user may accidentally set Neuron Encrypt as the default handler for binary files, then wonder why downloads open an encryption app instead of a file manager. No security impact: the app reads the file and detects magic bytes; if it's not a `.vx2` file, it offers to encrypt it (which the user can decline). The `pathPattern=".*\\.vx2"` is OR'd with the MIME type (both are `<data>` elements in the same intent-filter), so the filter matches EITHER condition, broadening the match.
- **Verification**: Read AndroidManifest.xml lines 22-28. Confirmed: two `<data>` elements (mimeType and pathPattern) in one intent-filter. Per Android intent-filter rules, multiple `<data>` elements in the same filter are combined with OR for the matching attributes, but the filter matches if ALL attribute categories (scheme, host, port, path, mimeType) have at least one matching element. Since only `mimeType` and `pathPattern` are specified (no scheme/host), the filter matches any intent with `application/octet-stream` MIME OR a `.vx2` path.
- **Suggested fix**: Split into two intent-filters: one for `.vx2` files (with a custom MIME type like `application/vnd.neuronencrypt.vx2` and the pathPattern), and optionally one for `ACTION_SEND` of `.vx2` files only. Drop the broad `application/octet-stream` MIME type — users can still use the in-app file picker to select any file. If the broad MIME is intentional (to allow "Open with Neuron Encrypt" for any binary), document the rationale.
- **Confidence**: High

### [INFO] Finding 6-24: GUI `truncate_chars` is O(n²) — double `chars().count()` on long strings
- **Location**: gui.rs:165-171 (`truncate_chars`)
- **Category**: code-quality / performance
- **Description**: `truncate_chars(s: &str, n: usize)` (lines 165-171) does: (1) `s.chars().take(n).collect::<String>()` — O(n), (2) `if s.chars().count() > n` — O(len(s)), (3) `out.push_str("...")`. The `s.chars().count()` at line 167 iterates the ENTIRE string to count characters, even though we only need to know if the count exceeds `n`. For a 10,000-character string truncated to 40, this does ~10,000 iterations just to check "is the count > 40?". The function is called frequently in the GUI (e.g., `truncate_chars(&filename, 42)` at line 936, `truncate_chars(&name, 44)` at line 1421, `truncate_chars(message, 120)` at line 1471, etc.) — typically on short strings (filenames, status messages), so the O(n²) doesn't matter in practice.
- **Impact**: Negligible. Filenames and status messages are typically <256 chars. The double-iteration is wasteful but unmeasurable. For very long strings (e.g., a 1MB error message), it would be noticeable — but no such call site exists.
- **Verification**: Read gui.rs lines 165-171. Confirmed: `s.chars().count()` at line 167 iterates the full string. `s.chars().take(n).collect()` at line 166 also iterates but only `n` chars. The double iteration is the issue.
- **Suggested fix**: Use `s.char_indices().nth(n)` to check if there's an (n+1)th character without counting the whole string: `if s.char_indices().nth(n).is_some() { out.push_str("..."); }`. Or restructure: collect the first `n+1` chars; if the (n+1)th exists, truncate to `n` and append "...". This is O(n) instead of O(len(s)).
- **Confidence**: High

---
Task ID: 7
Agent: Dynamic Verification & PoC Testing
Task: Verify Task 5 and Task 6 findings via byte-level PoC scripts and code re-reading; write test plan

Work Log:
- Re-read crypto.rs (1365 lines) focusing on: encrypt_file (395-511), decrypt_file_streaming (650-760), encrypt_stream (827-910), decrypt_stream_v3 (942-1004), decrypt_file_legacy (556-647), decrypt_stream_v2 (1006-1047), derive_key (159-176), derive_key_v3 (180-194), build_aad (196-201), parse_header (381-393), read_limited_file (259-264), test module (1049-1364).
- Re-read utils.rs (56 lines) — constant_time_eq (1-20).
- Re-read cli.rs (832 lines) — read_password (96-130), read_password_confirmed (133-148), run() password-binding & early-return paths (380-440), main() (827-832).
- Grepped crypto.rs for: `build_aad`, `Payload`, `aad`, `encrypt_next`, `encrypt_last`, `decrypt_next`, `decrypt_last`, `MAX_FILE_SIZE`, `MAX_ENCRYPTED`, `FileTooLarge`, `source_len`, `file_len` (all hit locations recorded in PoC scripts).
- Wrote 7 Python PoC/verification scripts in /home/z/my-project/scripts/:
    1. verify_v3_aad.py            — Task 7.1 (V3 AAD omission)
    2. verify_4tib_limit.py        — Task 7.2 (counter-overflow limit; corrected 4 TiB -> 4 PiB)
    3. poc_truncated_v3.py         — Task 7.3 (truncated V3 file PoCs)
    4. poc_chunk_reorder.py        — Task 7.4 (chunk reorder/truncate/extend PoCs)
    5. verify_v2_limit_inconsistency.py — Task 7.5 (V2 file vs stream 1 GiB boundary)
    6. verify_empty_file.py        — Task 7.6 (empty-file roundtrip trace)
    7. verify_constant_time.py     — Task 7.10 (constant_time_eq length-leak)
- Wrote test plan: /home/z/my-project/scripts/test_plan.md (23 proposed tests; Task 7.12).
- Executed all 7 Python scripts via /home/z/.venv/bin/python3 — all run cleanly, all assertions pass.
- Verified Tasks 7.7, 7.8, 7.9, 7.11 by code re-reading (no separate script required; reasoning recorded in stage summary below).

Stage Summary:

### [VERIFIED] Task 7.1: V3 streaming omits AAD (salt + stream_nonce not authenticated)
- **Original finding**: Task 5 Finding 5-1 (MEDIUM)
- **Verification method**: Re-read crypto.rs:415-500 (encrypt_file V3), 650-760 (decrypt_file_streaming), 827-910 (encrypt_stream), 942-1004 (decrypt_stream_v3). Grepped `build_aad` (4 hits, all in V2 paths at lines 328, 367, 593, 1031) and `Payload` (4 hits, all in V2 paths at lines 332, 371, 598, 1036). Grepped `encrypt_next`/`encrypt_last`/`decrypt_next`/`decrypt_last` (10 hits in V3 paths, all pass bare `&[u8]`). Wrote /home/z/my-project/scripts/verify_v3_aad.py.
- **Result**: CONFIRMED.
- **Evidence**:
  - V2 `encrypt_bytes` (line 328): `let aad = build_aad(&salt, &nonce_bytes);` then (line 332-335): `Payload { msg: plaintext, aad: &aad }`.
  - V2 `decrypt_bytes` (line 367): `let aad = build_aad(salt, nonce_bytes);` then (line 371-374): `Payload { msg: ciphertext, aad: &aad }`.
  - V2 `decrypt_file_legacy` (line 593): `let aad = build_aad(salt, nonce);` then (line 598-601): `Payload { msg: ciphertext, aad: &aad }`.
  - V2 `decrypt_stream_v2` (line 1031): `let aad = build_aad(&salt, &nonce);` then (line 1036-1039): `Payload { msg: &ciphertext, aad: &aad }`.
  - V3 `encrypt_file` (line 419): `EncryptorBE32::from_aead(cipher, (&stream_nonce).into())` — NO AAD seeded.
  - V3 calls (10 sites: lines 454, 475, 483, 719, 732, 863, 886, 893, 982, 994) all pass bare `&[u8]` → `aead` crate implicitly uses `Payload { msg, aad: &[] }`.
  - So V2 AAD = salt[32] || nonce[12] = 44 bytes; V3 AAD = b"" (empty).
- **Attack demonstration** (in verify_v3_aad.py): flipping bit 0 of salt[0] OR bit 3 of stream_nonce[0] changes the derived Argon2id+HKDF key (or the AEAD nonce prefix), causing every chunk's GCM-SIV tag to fail verification → `CryptoError::DecryptionFailed`. Changing the magic bytes `VAULTX03` → `VAULTX02` reroutes the dispatcher to the V2 path, which then fails on tag verification after misinterpreting the 31-byte V3 header as the first 31 bytes of a 52-byte V2 header. None of these attacks bypass encryption; the worst case is DoS (forced `DecryptionFailed`) or info leak via routing through a rarely-tested V2 code path.
- **Adjusted severity**: MEDIUM (defensive-in-depth; not exploitable beyond DoS). Same as Task 5.
- **Confidence**: High.

### [VERIFIED WITH MATH CORRECTION] Task 7.2: V3 has no enforcement of counter-overflow limit
- **Original finding**: Task 5 Finding 5-2 (MEDIUM) — claimed "4 TiB" boundary.
- **Verification method**: Re-read crypto.rs:395-511 (encrypt_file), 650-760 (decrypt_file_streaming), 827-910 (encrypt_stream), 942-1004 (decrypt_stream_v3). Grepped `MAX_FILE_SIZE` / `MAX_ENCRYPTED` / `FileTooLarge` — only hits in V2 paths (lines 61, 62, 572, 573-576). Wrote /home/z/my-project/scripts/verify_4tib_limit.py.
- **Result**: CONFIRMED with arithmetic correction.
- **Evidence**:
  - `MAX_FILE_SIZE = 8_000_000_000` (line 61, V2 only).
  - `MAX_ENCRYPTED_FILE_SIZE = MAX_FILE_SIZE + HEADER_LEN + TAG_LEN` (line 62).
  - Enforcement only at line 572 (`if source_len > MAX_ENCRYPTED_FILE_SIZE` in `decrypt_file_legacy` — V2 file path).
  - V3 paths (encrypt_file, decrypt_file_streaming, encrypt_stream, decrypt_stream_v3): NO `MAX_FILE_SIZE` / `FileTooLarge` references. The only V3 size gate is the small-file check at line 666 (`file_len < HEADER_V3_LEN + TAG_LEN` → `FileTooSmall`).
- **MATH CORRECTION**: Task 5 Finding 5-2 and the README both claim "2^32 chunks × 1 MiB = 4 TiB". This is incorrect:
    - 2^32 chunks × 1 MiB/chunk = 2^32 × 2^20 bytes = 2^52 bytes
    - 2^52 bytes = 4 × 2^50 bytes = **4 PiB** (pebibytes), NOT 4 TiB.
    - 4 TiB would be 2^42 bytes = 2^22 chunks (only 4,194,304 chunks).
  The actual EncryptorBE32 counter-wrap boundary at 1 MiB chunks is **4 PiB**, which is 1024× larger than the original finding stated. This makes the practical-exploitability concern even less realistic (4 PiB >> any plausible single-file size), but the underlying defect (no upper-bound check on V3 paths; silent counter wraparound if it ever happened) is real.
- **Adjusted severity**: MEDIUM (defensive hardening; practical exploitability is essentially nil for the foreseeable future, but the silent-failure mode justifies an explicit guard). Same as Task 5.
- **Confidence**: High.

### [VERIFIED] Task 7.3: Truncated V3 file PoC
- **Original finding**: Task 5 Finding 5-14 (INFO — chunk-level integrity verified safe)
- **Verification method**: Wrote /home/z/my-project/scripts/poc_truncated_v3.py. Constructed 4 synthetic V3 files at the byte level: (A) 47-byte valid-structure (31 header + 16 random tag), (B) 31-byte header-only, (C) 46-byte partial-tag, (D) 47-byte with all-zero tag. Documented expected `decrypt_file_streaming` behavior for each by citing crypto.rs lines.
- **Result**: CONFIRMED.
- **Evidence**:
  - Size gate at crypto.rs:666: `if file_len < HEADER_V3_LEN as u64 + TAG_LEN as u64 { return Err(CryptoError::FileTooSmall); }` (= 47 bytes).
  - Case A (47 B): passes size gate; KDF runs (~0.5s); `decrypt_last(16 B)` at line 731; tag mismatch on random bytes → `DecryptionFailed` (line 733).
  - Case B (31 B): rejected by size gate → `FileTooSmall` (line 667). No KDF cost.
  - Case C (46 B): rejected by size gate → `FileTooSmall`. No KDF cost.
  - Case D (47 B, zero tag): passes size gate; KDF runs; `decrypt_last(16 B)`; tag mismatch on zeros → `DecryptionFailed`.
- **Adjusted severity**: N/A (confirms existing safe behavior).
- **Confidence**: High.

### [VERIFIED] Task 7.4: Chunk-reorder / substitution / extension PoC
- **Original finding**: Task 5 Finding 5-14 (INFO — chunk-level integrity verified safe)
- **Verification method**: Wrote /home/z/my-project/scripts/poc_chunk_reorder.py. Built a synthetic 3-chunk V3 body (2 × 1 MiB intermediate + 1 KB last). Demonstrated 5 attacks: (A) reorder chunks 0 and 1, (B) truncate last 16 bytes (remove last tag), (C) truncate 8 bytes mid-tag, (D) append 32 random bytes after last tag, (E) copy an intermediate chunk and append after the last tag.
- **Result**: CONFIRMED.
- **Evidence**: All 5 attacks fail at the GCM-SIV tag verification step:
  - Attack A: chunk 1 (originally counter=1) is now at position 0 (counter=0) → nonce mismatch → `DecryptionFailed` (line 720).
  - Attack B: original last chunk's tag is gone; `decrypt_last` on a chunk without its tag → `DecryptionFailed` (line 733).
  - Attack C: last chunk is truncated; `decrypt_last` on a shorter chunk → tag mismatch → `DecryptionFailed` (line 733).
  - Attack D: original last chunk is now followed by garbage, so it gets promoted to `decrypt_next` (intermediate, flag=0); but it was sealed with `encrypt_last` (flag=1) → nonce mismatch → `DecryptionFailed` (line 720).
  - Attack E: original last chunk promoted to `decrypt_next` (flag mismatch), then copied intermediate chunk treated as `decrypt_last` (flag mismatch) → `DecryptionFailed`.
  - The BE32 internal flag byte (0=intermediate, 1=last) and 4-byte counter (implicit from chunk position) jointly prevent any chunk from being reinterpreted as a different chunk type or position.
  - Code uses `encrypt_next` for intermediate (line 483) and `encrypt_last` for final (lines 454, 475) on encrypt; `decrypt_next` (line 719) and `decrypt_last` (line 732) on decrypt. The `last_chunk` delay-by-one idiom (lines 705, 715, 725, 729) ensures no chunk is prematurely treated as final.
- **Adjusted severity**: N/A (confirms existing safe behavior).
- **Confidence**: High.

### [VERIFIED] Task 7.5: V2 file vs V2 stream 1 GiB limit inconsistency
- **Original finding**: Task 5 Finding 5-4 (LOW)
- **Verification method**: Re-read crypto.rs:581-584 (`decrypt_file_legacy`) and 1022-1029 (`decrypt_stream_v2`). Wrote /home/z/my-project/scripts/verify_v2_limit_inconsistency.py with a boundary-comparison table.
- **Result**: CONFIRMED.
- **Evidence**:
  - `decrypt_file_legacy` (line 581): `let raw = read_limited_file(file, 1_073_741_824u64)?;` — `read_limited_file` (line 260) uses `file.take(limit + 1)`, so it can read up to 1 GiB + 1 byte before truncation.
  - `decrypt_file_legacy` (line 582): `if raw.len() as u64 > 1_073_741_824u64` — strict GREATER-THAN. A 1 GiB body passes (`1_073_741_824 > 1_073_741_824` is false).
  - `decrypt_stream_v2` (line 1024-1026): `reader.take(V2_STREAM_MAX_BYTES).read_to_end(&mut ciphertext)?` — caps the read at EXACTLY 1 GiB (no +1).
  - `decrypt_stream_v2` (line 1027): `if ciphertext.len() as u64 >= V2_STREAM_MAX_BYTES` — GREATER-THAN-OR-EQUAL. A 1 GiB body FAILS (`1_073_741_824 >= 1_073_741_824` is true).
  - Net effect: a 1 GiB V2 body decrypts via `neuron-encrypt-cli decrypt -i file.vx2` but fails via `cat file.vx2 | neuron-encrypt-cli decrypt -i - -o out`.
- **Adjusted severity**: LOW (no security impact; user-visible annoyance only). Same as Task 5.
- **Confidence**: High.

### [VERIFIED] Task 7.6: Empty-file handling
- **Original finding**: Task 5 Finding 5-14 (INFO — empty-file case verified safe by trace)
- **Verification method**: Wrote /home/z/my-project/scripts/verify_empty_file.py. Traced `encrypt_file` (crypto.rs:395-511) for a 0-byte input and `decrypt_file_streaming` (crypto.rs:650-760) for the resulting 47-byte V3 file, line-by-line.
- **Result**: CONFIRMED CORRECT.
- **Evidence**:
  - Encrypt (0-byte input): line 450 `read_exact_or_eof` returns 0; line 451 `if n == 0` → TRUE; line 453-455 `encryptor.encrypt_last(&[][..])` returns 16-byte tag (GCM-SIV seals empty plaintext as 16-byte tag, no ciphertext bytes); line 456 writes tag; line 457 breaks. Total output = 31 (header) + 16 (tag) = 47 bytes.
  - Decrypt (47-byte input): line 666 size gate `47 < 47` is FALSE → pass; line 678 KDF runs; line 703 buf allocated (1 MiB + 16 B); line 708 loop iter 1: `read_exact_or_eof` reads 16 bytes → `last_chunk = Some(16 B)`; line 708 loop iter 2: reads 0 → break; line 729 `if let Some(final_data) = last_chunk` → TRUE; line 731-733 `decrypt_last(16 B)` returns empty plaintext on tag verification success; line 734 writes 0 bytes. Output = 0 bytes (matches original).
  - **No test currently covers this case** — see Task 7.12 test #1.
- **Adjusted severity**: N/A (confirms existing safe behavior; recommends adding a regression test).
- **Confidence**: High.

### [VERIFIED] Task 7.7: Empty-last-chunk edge case for multi-chunk files
- **Original finding**: Task 5 Finding 5-14 (INFO — chunk-level integrity verified safe by trace)
- **Verification method**: Code re-reading of crypto.rs:449-497 (encrypt loop) and 708-735 (decrypt loop). Traced two cases: (1) 1 MB input (exactly CHUNK_SIZE), (2) 2 MB input (exactly 2 × CHUNK_SIZE).
- **Result**: CONFIRMED CORRECT.
- **Evidence**:
  - **1 MB input**: `read_exact_or_eof` returns 1 MB (buf full); `peek` reads 1 byte, returns 0 (EOF); line 471 `if peeked == 0` → TRUE; line 474-476 `encrypt_last(&buf[..1MB])`. Output = 31 + (1 MB + 16) = 1,048,623 bytes. On decrypt: `read_exact_or_eof` reads 1MB+16, returns 1MB+16; `last_chunk = Some(1MB+16)`; next read returns 0; `decrypt_last(1MB+16)` → 1 MB plaintext. ✓
  - **2 MB input**: First `read_exact_or_eof` returns 1 MB; `peek` returns 1 (more data); line 482-484 `encrypt_next(1MB)`; seek back 1 byte. Second `read_exact_or_eof` returns 1 MB; `peek` returns 0 (EOF); `encrypt_last(1MB)`. Output = 31 + 2 × (1MB + 16) = 2,097,215 bytes. On decrypt: first `read_exact_or_eof` reads 1MB+16 → `last_chunk = Some(1MB+16)`; second `read_exact_or_eof` reads 1MB+16 → `last_chunk.take()` returns FIRST chunk, decrypts with `decrypt_next` (correct, because we now have a new last_chunk); third `read_exact_or_eof` returns 0 → break; `decrypt_last` on SECOND chunk → 1 MB plaintext. ✓
  - The `last_chunk` delay-by-one idiom (lines 705, 715, 725, 729) is the standard streaming-AEAD pattern: you can't know if a chunk is the last until you try to read the next one. Verified correct.
- **Adjusted severity**: N/A.
- **Confidence**: High.

### [VERIFIED] Task 7.8: Password length check (byte length, not char length)
- **Original finding**: Not explicitly a Task 5/6 finding; minor doc issue noted in Task 5 Finding 5-15.
- **Verification method**: Grepped `MIN_PASSWORD_LEN` in crypto.rs — 6 enforcement sites: lines 316 (`encrypt_bytes`), 348 (`decrypt_bytes`), 402 (`encrypt_file`), 534 (`decrypt_file`), 834 (`encrypt_stream`), 921 (`decrypt_stream`). All use `if password.len() < MIN_PASSWORD_LEN` (byte length).
- **Result**: CONFIRMED — `MIN_PASSWORD_LEN = 8` is enforced at all 6 entry points on BYTE length.
- **Evidence**:
  - `password.len()` in Rust returns the BYTE length of the `&[u8]` slice, not the character count.
  - For ASCII passwords, byte length == char length.
  - For multi-byte UTF-8 (e.g., 8 emojis = 32 bytes UTF-8), byte length > char length. An 8-emoji password (8 chars, 32 bytes) passes the `>= 8` check.
  - This is the CORRECT measure because Argon2id treats the password as raw bytes (`hash_password_into(password, salt, &mut intermediate)` at lines 167, 187).
  - **Is this a bug?** No. The only issue is documentation: `MIN_PASSWORD_LEN` should be documented as "8 bytes" rather than "8 characters" (the latter is what the CLI error message says at cli.rs:429: `"Passphrase too short (minimum {} characters)."`).
- **Adjusted severity**: INFO (minor doc mismatch; no security impact).
- **Confidence**: High.

### [VERIFIED SAFE] Task 7.9: Zeroize-on-exit concern
- **Original finding**: Implicit concern from Task 6 (cli.rs main() uses `std::process::exit` which bypasses drop handlers).
- **Verification method**: Re-read cli.rs:380-440 (run() password-binding and early-return paths) and 827-832 (main). Traced all `return Err(...)` paths in run() to confirm `password: Zeroizing<String>` is always dropped via normal scope-unwinding before main() calls `process::exit`.
- **Result**: VERIFIED SAFE.
- **Evidence**:
  - `main()` (cli.rs:827-832): `match run() { Ok(()) => std::process::exit(0), Err(code) => std::process::exit(code as i32) }`. `std::process::exit` does NOT run drop handlers — BUT `run()` returns normally (via `return Err(code)` or end-of-scope), and normal returns DO drop all locals in scope.
  - `password: Zeroizing<String>` is bound at cli.rs:384 (`let password = match ... { ... }`).
  - Early-return paths BEFORE line 384 (e.g., `return Err(code)` at lines 396, 409 inside the match arms): `password` is NOT yet bound — no Zeroizing to drop. Safe.
  - Early-return path AFTER line 384 (line 431: `return Err(ExitCode::BadInput)` for password-too-short): `password` IS bound. `return Err(...)` is a normal return (not an unwind); it triggers normal drop of all locals in `run()`'s scope, including `password`. The `Zeroizing<String>` Drop impl calls `zeroize()` on the inner String, wiping the password bytes. Safe.
  - After the encrypt/decrypt call (line 525: `password.as_bytes()` is a borrow, not a move), `password` is still owned by `run()`. When `run()` returns Ok or Err, `password` is dropped normally. Safe.
  - The only way to bypass drop is `std::process::exit` called from INSIDE `run()` — but there are no such calls (all `process::exit` calls are in `main()`). Also `panic = "abort"` (Cargo.toml:54) would bypass drops on panic, but no panic is expected in `run()`.
  - **Conclusion**: The `gt/birch` fix (changing `read_password` to return `Result` instead of calling `process::exit` internally) means all password-construction happens via the `?` operator or explicit match arms, and all error paths drop `password` normally. The Zeroize-on-exit concern is fully mitigated.
- **Adjusted severity**: INFO (no issue).
- **Confidence**: High.

### [VERIFIED] Task 7.10: constant_time_eq leaks the longer input length
- **Original finding**: Task 5 Finding 5-5 (LOW)
- **Verification method**: Re-read utils.rs:1-20. Wrote /home/z/my-project/scripts/verify_constant_time.py — reimplemented the Rust function in Python, ran correctness tests (10 cases, all pass), and demonstrated the loop iteration count = `max(len_a, len_b)`.
- **Result**: CONFIRMED.
- **Evidence**:
  - utils.rs:8 `for i in 0..max_len` — loop iterates `max(len_a, len_b)` times. Iteration count is observable via timing → leaks the longer input's length.
  - utils.rs:14-15 length-equality bit trick: `len_diff = len_a ^ len_b; len_mismatch_flag = ((len_diff | len_diff.wrapping_neg()) >> (usize::BITS - 1)) & 1`. In two's complement, `x | -x` has the high bit set iff `x != 0`. This IS constant-time with respect to the length values — but it runs AFTER the loop has already leaked `max(len_a, len_b)`.
  - utils.rs:9-10 `a.get(i).unwrap_or(&0)` introduces a data-dependent `Option` discriminant branch per iteration (LLVM may compile to branchless `cmov`).
  - Call sites (from Task 5): gui.rs:413, 507, 1150, 1211, 1530, 1550 + cli.rs:163 — all in `read_password_confirmed` paths comparing two user-typed passwords. Both inputs are user-typed, so the attacker already knows the length of both. No secret comparison. No exploit in current usage.
  - **Misleading name**: `constant_time_eq` suggests it's safe for comparing secrets. If anyone uses it to compare a secret (e.g., HMAC tag, session token) against an untrusted input, the length leak would be exploitable.
- **Adjusted severity**: LOW (info-level in practice; MEDIUM if used elsewhere). Same as Task 5.
- **Suggested fix**: Replace with `subtle::ConstantTimeEq` (RustCrypto), or rename to `constant_time_eq_same_length` and document the limitation.
- **Confidence**: High.

### [VERIFIED] Task 7.11: V2 AAD includes salt+nonce but V3 does NOT
- **Original finding**: Task 5 Finding 5-1 (MEDIUM) — same finding as Task 7.1, with additional impact analysis.
- **Verification method**: Same as Task 7.1 (grepped `build_aad`, `Payload`, `aad` in crypto.rs). Confirmed V2 AAD = salt[32] || nonce[12] = 44 bytes; V3 AAD = b"" (empty).
- **Result**: CONFIRMED.
- **Evidence**: See Task 7.1 evidence. V2 call sites (4) all pass `Payload { msg, aad: &aad }`. V3 call sites (10) all pass bare `&[u8]` → `aead` crate uses `Payload { msg, aad: &[] }`.
- **Impact analysis**:
  1. Flip bits in V3 salt → changes derived Argon2id+HKDF key → all chunk tags fail → `DecryptionFailed`. DoS only.
  2. Flip bits in V3 stream_nonce → changes AEAD nonce prefix → all chunk tags fail → `DecryptionFailed`. DoS only.
  3. Flip magic bytes V3→V2 → reroutes dispatcher to V2 path, which misinterprets the 31-byte V3 header as 52-byte V2 header bytes, runs Argon2id on garbage salt → tag fails → `DecryptionFailed`. DoS + exercises rarely-tested V2 code path.
- **Practical impact**: DoS, not plaintext recovery. Deviation from best practice (AEAD should authenticate all metadata).
- **Adjusted severity**: MEDIUM (defensive-in-depth; not exploitable beyond DoS). Same as Task 5.
- **Suggested fix**: Extend `build_aad` to cover `MAGIC_V3 || salt || stream_nonce` (35 bytes), pass `Payload { msg, aad }` on every V3 stream call. Breaking format change → bump to V4.
- **Confidence**: High.

### Task 7.12: Test plan
- **Deliverable**: /home/z/my-project/scripts/test_plan.md
- **Content**: 23 proposed tests (4 already exist, 2 explicitly skipped due to performance, 17 net-new). Covers: empty file, single byte, exact chunk, exact 2-chunk, multi-chunk with partial last, truncated at chunk boundary, truncated mid-chunk, tampered salt, tampered nonce, tampered magic (V3→V2), tampered chunk byte, reordered chunks, counter boundary (skipped), wrong password (exists), V2 backward compat (exists), V2→V3 confusion, large file (skipped), password boundary (7 vs 8 bytes), password UTF-8 boundary, Argon2id param verification, HKDF info domain separation, V2 stream 1 GiB boundary (regression), header-only via stream (exists), header-only via file mode.
- **Priority ranking**: HIGH = truncation/tamper/reorder tests (5,6,7,8,10,11) + empty file (1) + magic-swap (9,15). MEDIUM = boundary cases (2,3,4) + password policy (17,18) + primitive locking (19,20). LOW = perf-skipped (21) + minor variants (23).

---

Files written by Task 7:
- /home/z/my-project/scripts/verify_v3_aad.py
- /home/z/my-project/scripts/verify_4tib_limit.py
- /home/z/my-project/scripts/poc_truncated_v3.py
- /home/z/my-project/scripts/poc_chunk_reorder.py
- /home/z/my-project/scripts/verify_v2_limit_inconsistency.py
- /home/z/my-project/scripts/verify_empty_file.py
- /home/z/my-project/scripts/verify_constant_time.py
- /home/z/my-project/scripts/test_plan.md

All Python scripts execute cleanly under /home/z/.venv/bin/python3 (stdlib only, no pip installs).

---
Task ID: A
Agent: Adversarial Crypto Attack Review
Task: Find any way to break Neuron Encrypt v2.1.0's cryptography

Work Log:
- Read /home/z/my-project/worklog.md (642 lines) — prior audits: Task 5 (crypto deep-review, 20 findings), Task 6 (code-quality, 24 findings), Task 7 (dynamic PoC verification, 11 verified tasks + test plan). Confirmed I must NOT repeat: V3 AAD omission (5-1), V3 4PiB limit (5-2, fixed), test gaps (5-3, fixed via P2-1 tests), V2 1GiB inconsistency (5-4, fixed in audit-patches), constant_time_eq length leak (5-5), HKDF None salt (5-6), 32-of-64 byte usage (5-7), tmp-path entropy (5-8), parse_header redundant magic check (5-9), decrypt_file double-open (5-10), Zeroizing coverage (5-11), OsRng usage (5-12), error side-channels (5-13), chunk integrity (5-14), MIN_PASSWORD_LEN=8 (5-15), mutex poisoning (5-16), RustCrypto deps (5-17), Argon2id params (5-18), HKDF info domain separation (5-19), V2<->V3 cross-format confusion (5-20).
- Read crypto.rs (1711 lines), error.rs (62 lines), utils.rs (68 lines) in full.
- CRITICAL PREMISE CHECK: Grepped crypto.rs for `VAULTX04|MAGIC_V4|derive_key_v4|build_aad_v4|MAX_V4|HEADER_V4` → 0 matches. Grepped for `cancel|AtomicBool|Cancelled` → 0 matches. Read Cargo.toml line 3: `version = "2.0.0"`. Git log: HEAD is commit 4344401 on branch `fix/audit-patches`; `git tag` shows only v1.0 and v2.0 (no v2.1.0). The task description's premise (V4/VAULTX04, cancellation, v2.1.0, fix/audit-patches merged to main) does NOT match the actual codebase. V4 and cancellation do not exist; the code is v2.0.0 with audit patches applied on a feature branch. I audited the ACTUAL code (V2 + V3, no V4, no cancellation).
- Attack vectors tried:
  1. V4 AAD mismatch between encrypt/decrypt — N/A (V4 doesn't exist).
  2. Cancellation race conditions — N/A (no cancellation logic exists).
  3. Downgrade V4->V3->V2 magic swap — re-verified V3->V2 and V2->V3 (already covered by Task 7.1 / test_v3_magic_swap_v3_to_v2_fails). No new finding.
  4. Chunk-boundary counter overflow at 2^32 — re-verified the MAX_V3_FILE_SIZE guard in encrypt_file (line 419, correct) and encrypt_stream (line 855-862). Found the guard in encrypt_stream is INSIDE `if let Some(size) = source_size` — skipped when source_size=None. NEW finding A-2.
  5. Memory hygiene regression — re-scanned all V3 buffers. Found `peek` 1-byte stack buffer (lines 484, 906) is NOT Zeroizing. NEW finding A-5.
  6. Argon2id parameter confusion — grepped `Params::new` and `Argon2::new`: only 2 call sites (derive_key line 171, derive_key_v3 line 191), identical params. No drift. No new finding.
  7. RNG misuse — grepped `OsRng|thread_rng|SmallRng|StdRng|from_seed|from_entropy`: only OsRng used. No new finding.
  8. Error side-channels — re-checked all error variants. Found decrypt_stream_v3 runs Argon2id BEFORE discovering a header-only body (no pre-Argon2id size check), inconsistent with decrypt_file_streaming. NEW finding A-4.
  9. Test coverage gaps for V4 — N/A (V4 doesn't exist). Re-verified existing V3 tests cover empty/single-byte/truncation/tamper/reorder/extend/magic-swap/boundary. No new gap.
  10. Supply chain — re-read Cargo.lock. 531 packages. Crypto deps unchanged from Task 5-17. No new finding.
  11. secure_wipe TOCTOU — read lines 782-839. `symlink_metadata` (783) checks not-a-symlink, but `OpenOptions::new().write(true).open(path)` (793) follows symlinks with no O_NOFOLLOW. Race window between check and open. NEW finding A-3.
  12. V2 AAD missing MAGIC — re-read build_aad (204-209). AAD = salt||nonce, no MAGIC. Defense-in-depth gap, not exploitable (dispatcher checks magic). NEW finding A-7 (INFO).
  13. chunk_counter unused for overflow detection — lines 462/502 (encrypt_file) and 882/922 (encrypt_stream). Tracked but only used for I/O governor. Not checked against 2^32. NEW finding A-6.
  14. Plaintext recovery attempts — considered: nonce-reuse via counter overflow (>4 PiB, impractical), TOCTOU file-swap in decrypt_file double-open (tag fails, no leak), Argon2id timing oracle (all paths run Argon2id before tag check, no oracle), error-message oracle (all failures return identical DecryptionFailed). No plaintext recovery attack found. The crypto core is solid for practical threat models.

Stage Summary:

### [INFO] Finding A-1: Task description premise does NOT match the codebase — V4/cancellation/v2.1.0 do not exist
- **Location**: Cargo.toml:3 (`version = "2.0.0"`); crypto.rs (grep for VAULTX04/MAGIC_V4/derive_key_v4/cancel/AtomicBool/Cancelled → 0 matches); git log (HEAD = 4344401 on `fix/audit-patches`, tags = v1.0, v2.0 only)
- **Category**: scope / premise-mismatch
- **Attack**: N/A — this is a meta-finding. The task description asks me to attack V4 AAD, cancellation races, V4->V3 downgrade, etc. None of these exist in the code. An attacker cannot exploit V4 because V4 has not been implemented. I audited the ACTUAL code (V2 + V3 only) and report new findings below.
- **Verification**: `grep -n "VAULTX04\|MAGIC_V4\|derive_key_v4\|build_aad_v4\|MAX_V4\|HEADER_V4" crypto.rs` → 0 hits. `grep -n "cancel\|AtomicBool\|Cancelled" crypto.rs` → 0 hits. `git tag` → v1.0, v2.0 (no v2.1.0). `git branch` → current branch is `fix/audit-patches` (NOT merged to main per `git log main..fix/audit-patches`).
- **Suggested fix**: Reconcile the task description with the codebase. If V4/cancellation are planned, implement them before requesting an adversarial review of them. If the task description was auto-generated from a spec, verify the spec matches the code before auditing.
- **Confidence**: High
- **Is this a regression from v2.0?**: No (the code IS v2.0; the task description's v2.1.0 is fictional)

### [MEDIUM] Finding A-2: `encrypt_stream` with `source_size = None` skips the 4 PiB counter-overflow guard — catastrophic nonce-reuse / data-loss path
- **Location**: crypto.rs:854-862 (guard), 882 (chunk_counter), 919-921 (encrypt_next call)
- **Category**: crypto / nonce-reuse / API-safety
- **Attack**: 
  1. A library consumer (GUI, JNI, or third-party) calls `encrypt_stream(reader, writer, password, None, reporter)` — the public API explicitly allows `source_size: Option<u64>`.
  2. The guard at line 855 is `if let Some(size) = source_size { ... }` — when `source_size` is `None`, the ENTIRE guard is skipped. No size check, no chunk-count check.
  3. The caller pipes a stream longer than 2^32 × 1 MiB (4 PiB) into `encrypt_stream`. The `chunk_counter` (line 882) increments per intermediate chunk but is ONLY used for the I/O governor sleep cadence (line 924) — it is NEVER compared against 2^32.
  4. On the (2^32 + 1)-th `encrypt_next` call (line 919), the `EncryptorBE32` internal 4-byte big-endian counter wraps from 0xFFFFFFFF back to 0x00000000. The nonce for this chunk becomes identical to the nonce for chunk 0: `stream_nonce(7) || counter=0(4) || flag=0(1)`.
  5. Two different plaintext chunks are now encrypted under the same (key, nonce) pair. For AES-GCM-SIV, this is NOT as catastrophic as plain GCM (SIV is misuse-resistant), but it still leaks the XOR of the two plaintext chunks and may allow tag forgery. If the aead crate returns `Err` on counter overflow instead of wrapping, the encryption aborts AFTER 2^32 chunks have been written to the output — but `encrypt_last` was never called, so the output is permanently unrecoverable (the decryptor will treat the last intermediate chunk as `decrypt_last`, flag mismatch → DecryptionFailed). Either outcome is bad.
- **Verification**: Read crypto.rs:843-936. Line 855: `if let Some(size) = source_size`. Line 882: `let mut chunk_counter: u64 = 0;`. Line 922: `chunk_counter += 1;`. Line 924: `if chunk_counter % IO_GOVERNOR_INTERVAL == 0` — only use of chunk_counter. No `if chunk_counter >= (1<<32)` check anywhere. Confirmed CLI passes `None` only for stdin-decrypt (cli.rs:621-626), and stdin-ENCRYPT is rejected at cli.rs:653-666, so the current CLI never triggers this — but the `pub fn` API is unsafe for any other caller.
- **Suggested fix**: Add a runtime guard inside the loop, before `encrypt_next`: `if chunk_counter >= (1u64 << 32) { return Err(CryptoError::FileTooLarge { size_gb: (chunk_counter as f64 * CHUNK_SIZE as f64) / 1e9, max_gb: MAX_V3_FILE_SIZE as f64 / 1e9 }); }`. This catches the overflow regardless of whether `source_size` was provided. Also update the comment at line 854 from "if the caller knows the size" to "regardless of whether the size is known".
- **Confidence**: High
- **Is this a regression from v2.0?**: No — the pre-audit code had NO guard at all (Task 5-2). The audit-patch added a guard but made it conditional on `source_size`, leaving the `None` case unguarded. This is an incomplete fix.

### [MEDIUM] Finding A-3: `secure_wipe` TOCTOU symlink race — attacker can destroy arbitrary file via symlink swap
- **Location**: crypto.rs:782-839 (secure_wipe), specifically line 783 (symlink_metadata check) vs line 793 (open without O_NOFOLLOW)
- **Category**: race / TOCTOU / symlink-attack
- **Attack**:
  1. Victim encrypts a file `victim.txt` in a shared directory (e.g., `/tmp`, `/shared`) and clicks "Wipe Source File" in the GUI/Android app, which calls `secure_wipe(path)`.
  2. `secure_wipe` calls `fs::symlink_metadata(path)` (line 783) → confirms `victim.txt` is a regular file (not a symlink).
  3. Attacker (who has write access to `/shared`) races to `rename(victim.txt, victim.bak)` then `symlink("/home/victim/.ssh/id_rsa", victim.txt)` in the microsecond window between line 783 and line 793.
  4. `secure_wipe` calls `fs::OpenOptions::new().write(true).open(path)` (line 793) — this follows the symlink and opens `/home/victim/.ssh/id_rsa` for writing.
  5. The 3-pass random overwrite (lines 796-808) destroys the SSH private key content.
  6. The rename-and-delete at lines 819-832 renames `victim.txt` (the symlink) to a random name and removes it — the symlink target is unaffected (the data was already destroyed in step 5).
- **Verification**: Read crypto.rs:782-839. Line 793: `fs::OpenOptions::new().write(true).open(path)` — no `O_NOFOLLOW`, no `custom_flags`, no `OpenOptionsExt::mode`. Grepped for `O_NOFOLLOW` and `custom_flags` in crypto.rs → 0 hits. The `OpenOptionsExt` import at lines 441, 627, 706 is used ONLY for `.mode(0o600)` on temp files, not for `O_NOFOLLOW`. The `secure_wipe` function does NOT use `OpenOptionsExt` at all — it uses the plain `OpenOptions::new().write(true).open()`. On Unix, `open(2)` without `O_NOFOLLOW` follows symlinks. Classic TOCTOU.
- **Suggested fix**: On Unix, open with `O_NOFOLLOW`: 
  ```rust
  #[cfg(unix)]
  let mut file = {
      use std::os::unix::fs::OpenOptionsExt;
      fs::OpenOptions::new()
          .write(true)
          .custom_flags(libc::O_NOFOLLOW)  // refuse to follow symlink
          .open(path)?
  };
  ```
  On Windows, use `FILE_FLAG_OPEN_REPARSE_POINT` to prevent following mount points/junctions. Alternatively, open the file via `openat2(dirfd, path, RESOLVE_NO_SYMLINKS)` on Linux 5.6+ for full path-component protection.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — this TOCTOU has existed since `secure_wipe` was written. Not previously audited (Task 5/6/7 focused on crypto correctness, not secure_wipe races).

### [LOW] Finding A-4: `decrypt_stream_v3` runs Argon2id BEFORE discovering a header-only body — CPU DoS and mode-detection timing oracle
- **Location**: crypto.rs:968-1030 (decrypt_stream_v3), specifically line 981 (derive_key_v3 / Argon2id) vs line 1023-1024 (FileTooSmall after loop)
- **Category**: side-channel / DoS / inconsistency
- **Attack**:
  1. Attacker sends a 31-byte stream (8 magic `VAULTX03` + 16 salt + 7 nonce, NO body) to a service that calls `decrypt_stream` (e.g., a pipe-based decryption service, or the CLI `cat header-only.vx2 | neuron-encrypt-cli decrypt -i - -o -`).
  2. `decrypt_stream` dispatches to `decrypt_stream_v3` (line 960). There is NO pre-Argon2id size check in the stream path.
  3. `decrypt_stream_v3` reads salt+nonce (lines 977-978), then runs `derive_key_v3` (line 981) — full Argon2id, ~0.5s of CPU.
  4. The loop (line 990) reads 0 bytes immediately. `last_chunk` stays `None`.
  5. The function returns `CryptoError::FileTooSmall` (line 1024) — AFTER burning ~0.5s of CPU on Argon2id.
  6. Compare with `decrypt_file_streaming` (file mode): line 682 checks `file_len < HEADER_V3_LEN + TAG_LEN` BEFORE Argon2id (line 694) and returns `FileTooSmall` instantly.
  7. Timing oracle: an attacker who sends a 31-byte V3 file and measures response time can distinguish file-mode decrypt (instant FileTooSmall) from stream-mode decrypt (~0.5s FileTooSmall). This reveals which code path a service uses. Low-severity info leak.
  8. CPU DoS: an attacker who can submit many 31-byte streams to a stream-decrypt endpoint forces ~0.5s of Argon2id per request — amplification factor of ~1000x vs the attacker's bandwidth cost.
- **Verification**: Read crypto.rs:666-684 (decrypt_file_streaming — size check at 682 BEFORE Argon2id at 694). Read crypto.rs:968-1030 (decrypt_stream_v3 — Argon2id at 981, FileTooSmall at 1024 AFTER loop). Confirmed: no size check in the stream path before Argon2id. The `decrypt_stream` dispatcher (line 940-966) reads 8 magic bytes and dispatches — no size check either.
- **Suggested fix**: After reading salt+nonce (line 978), add a one-byte lookahead: `let mut peek = [0u8; 1]; if reader.read(&mut peek)? == 0 { return Err(CryptoError::FileTooSmall); }` then seek back (requires `R: Read + Seek`) or buffer the byte. Alternatively, require the caller to pass `total_size` and check it before Argon2id. The simplest fix: change `decrypt_stream` to require `R: Read + Seek` (like `encrypt_stream` does) and peek one body byte before running Argon2id.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — this inconsistency has existed since V3 was introduced. Not previously audited.

### [LOW] Finding A-5: `peek` byte buffer (1 byte of plaintext) is NOT Zeroizing — minor stack-resident plaintext residue
- **Location**: crypto.rs:484 (`let mut peek = [0u8; 1];` in encrypt_file), crypto.rs:906 (same in encrypt_stream)
- **Category**: memory / hygiene
- **Attack**: The 1-byte `peek` array holds the first byte of the next plaintext chunk. It's read from the source file at line 485/907 (`file.read(&mut peek)` / `reader.read(&mut peek)`). The byte is then "put back" via `seek(SeekFrom::Current(-1))` at line 511/929, so the next `read_exact_or_eof` re-reads it into `buf` (which IS Zeroizing). But the `peek` array itself — a stack-allocated `[u8; 1]` — retains that plaintext byte until the next loop iteration overwrites it (or until the function returns and the stack frame is reused). An attacker with the ability to read process memory (e.g., via a core dump, /proc/pid/mem, or a cold-boot attack) could recover 1 byte of plaintext per chunk boundary from the stack. The impact is tiny (1 byte per 1 MiB of plaintext), but it breaks the otherwise-comprehensive Zeroizing regime documented in Task 5-11.
- **Verification**: Read crypto.rs:484-511 (encrypt_file) and 906-929 (encrypt_stream). `peek` is `[0u8; 1]` — a plain stack array, NOT `Zeroizing<[u8; 1]>`. All other plaintext-bearing buffers (`buf` at 460/880, `pt` at 734/747/1007/1019, `last_chunk` at 721/741/988/1014) are `Zeroizing<T>`. The `peek` byte is the sole exception.
- **Suggested fix**: Replace `let mut peek = [0u8; 1];` with `let mut peek = Zeroizing::new([0u8; 1]);` and pass `peek.as_mut_slice()` to `read`. Alternatively, avoid the peek entirely by reading one extra byte into `buf` (if `n < CHUNK_SIZE`, it's the last chunk; if `n == CHUNK_SIZE`, peek separately — but this requires a different buffer strategy). The Zeroizing fix is simplest.
- **Confidence**: High (observation certain; severity Low — 1 byte per MiB)
- **Is this a regression from v2.0?**: No — the peek idiom has existed since V3 was introduced. Not previously audited.

### [LOW] Finding A-6: `chunk_counter` is tracked but never checked against 2^32 in either encrypt path — missing defense-in-depth runtime guard
- **Location**: crypto.rs:462, 502 (encrypt_file); crypto.rs:882, 922 (encrypt_stream)
- **Category**: crypto / defense-in-depth
- **Attack**: The `chunk_counter: u64` is incremented for every intermediate chunk (line 502 / 922) but is ONLY used to gate the I/O governor sleep (line 505 / 924: `if chunk_counter % IO_GOVERNOR_INTERVAL == 0`). It is NEVER compared against `2^32`. In `encrypt_file`, the pre-flight guard at line 419 (`source_len > MAX_V3_FILE_SIZE`) prevents overflow IF the file doesn't change size between `metadata()` (line 414) and the reads (line 466+). But if the source file GROWS during encryption (e.g., another process appends to it, or it's a special file like a /proc entry that returns variable-length data), `source_len` is stale, the guard passes, and the loop could in theory run past 2^32 chunks. In `encrypt_stream`, the guard is conditional on `source_size` (Finding A-2), so `chunk_counter` is the ONLY runtime signal available — and it's unused. Defense-in-depth: a runtime `chunk_counter` check would catch both the stale-size case (encrypt_file) and the None-size case (encrypt_stream).
- **Verification**: Read crypto.rs:462-513 (encrypt_file loop) and 882-931 (encrypt_stream loop). Grepped `chunk_counter` → 6 hits (declaration, increment, modulus check at 505/924). No comparison against `2^32` or `MAX_V3_FILE_SIZE / CHUNK_SIZE`. Confirmed: the runtime counter is available but unused for overflow detection.
- **Suggested fix**: Inside both encrypt loops, before the `encrypt_next` call, add: `if chunk_counter >= (1u64 << 32) { return Err(CryptoError::FileTooLarge { size_gb: (chunk_counter as f64 * CHUNK_SIZE as f64) / 1_000_000_000.0, max_gb: MAX_V3_FILE_SIZE as f64 / 1_000_000_000.0 }); }`. This is a cheap (one comparison per chunk) defense-in-depth guard that catches both the stale-size and unknown-size cases.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — `chunk_counter` has been tracked since V3 was introduced but was never used for overflow detection. The pre-flight guard (added in audit-patches) is the only protection, and it has the stale-size gap.

### [INFO] Finding A-7: V2 `build_aad` does not include MAGIC bytes — defense-in-depth gap (not exploitable)
- **Location**: crypto.rs:204-209 (build_aad), called at lines 336, 375, 609, 1057
- **Category**: crypto / defense-in-depth
- **Attack**: `build_aad(salt, nonce)` constructs AAD = salt[32] || nonce[12] = 44 bytes. The 8-byte MAGIC (`VAULTX02`) is NOT included. An attacker who modifies ONLY the magic bytes (keeping salt+nonce identical) would NOT trigger an AAD mismatch on the V2 AEAD tag. In practice this is NOT exploitable because: (a) the dispatcher at crypto.rs:562-568 checks the magic and routes to `decrypt_file_legacy` (V2) or `decrypt_file_streaming` (V3) — a magic change reroutes to a different KDF (derive_key vs derive_key_v3, different HKDF info strings), producing a wrong AES key, causing tag failure; (b) changing the magic to an unknown value returns `InvalidMagic` immediately. So the magic IS implicitly authenticated through the dispatcher + KDF domain separation. But the V2 AAD does not CRYPTOGRAPHICALLY bind the format version — if a future refactor moved the magic check out of the dispatcher (or added a new format that reuses the V2 KDF), the magic would become unauthenticated. The planned V4 (per task description) would fix this by including MAGIC_V4 in the AAD, but V4 does not exist in the code.
- **Verification**: Read crypto.rs:204-209. `build_aad` concatenates `salt` and `nonce` only — no MAGIC. Grepped `build_aad` → 4 call sites (336, 375, 609, 1057), all in V2 paths. V3 paths (encrypt_file, decrypt_file_streaming, encrypt_stream, decrypt_stream_v3) do NOT call `build_aad` at all (V3 AAD = empty, covered in Task 5-1). So neither V2 nor V3 authenticates the magic in AAD.
- **Suggested fix**: When implementing V4, define `build_aad_v4(magic, salt, stream_nonce)` = magic[8] || salt[16] || stream_nonce[7] = 31 bytes, and pass it to every `encrypt_next`/`encrypt_last`/`decrypt_next`/`decrypt_last` call. For V2, optionally extend `build_aad` to `magic || salt || nonce` (48 bytes) — but this is a breaking format change requiring a version bump, so defer to V4.
- **Confidence**: High (observation certain; not exploitable in current code)
- **Is this a regression from v2.0?**: No — V2 AAD has never included MAGIC. This is a long-standing defense-in-depth gap.

### [INFO] Finding A-8: `eprintln!` in V2 decrypt paths emits format-version info to stderr — minor operational info leak
- **Location**: crypto.rs:595 (decrypt_file_legacy), crypto.rs:1038 (decrypt_stream_v2)
- **Category**: side-channel / operational
- **Attack**: Both V2 decrypt paths emit `eprintln!("[INFO] VAULTX02 (V2) format detected. Consider re-encrypting with V3 for streaming support and no memory limits.")`. If a service captures stderr to a log file (common practice), the log reveals that a V2-format file was decrypted and the timestamp. The format version is already known to the user (they're decrypting their own file), but if the service is multi-user or the log is world-readable, this leaks which files are V2 vs V3. Not a crypto issue — operational hygiene.
- **Verification**: Read crypto.rs:595 and 1038. Both are `eprintln!` calls writing a fixed string to stderr. Grepped `eprintln!` in crypto.rs → 2 hits (both V2 info messages). V3 paths have no such messages.
- **Suggested fix**: Gate behind a `--verbose` flag, or return the format version via the `ProgressReporter` trait instead of stderr. Or remove entirely — the format version is not actionable for the user during decryption.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — these messages have existed since V3 was introduced to encourage migration.

### [INFO] Finding A-9: `fix/audit-patches` branch is NOT merged to main — users building from main get pre-audit code
- **Location**: git repository — `git log main..fix/audit-patches` shows commit 4344401 is on `fix/audit-patches` but not on `main`
- **Category**: supply-chain / release-management
- **Attack**: The task description claims "fix/audit-patches branch was merged to main." Git history contradicts this: `main` is at commit 343d3b3 (Merge branch 'main'), while `fix/audit-patches` is at 4344401 (Security audit: apply P0/P1/P2 fixes). A user who clones `main` and builds gets code WITHOUT the MAX_V3_FILE_SIZE guard, WITHOUT the V2 1GiB consistency fix, WITHOUT the P2-1 regression tests, and WITHOUT any of the P0/P1 fixes from Task 6. This means the Task 5-2 nonce-reuse vulnerability (no 4 PiB limit) is still present in `main` builds.
- **Verification**: `git branch -a` → `* fix/audit-patches` (current), `main`, `remotes/origin/main`. `git log --oneline main -1` → `343d3b3 Merge branch 'main'`. `git log --oneline fix/audit-patches -1` → `4344401 Security audit`. `git log main..fix/audit-patches --oneline` → shows 4344401 is NOT on main. Confirmed: the audit fixes are uncommitted to main.
- **Suggested fix**: Merge `fix/audit-patches` to `main` and tag as `v2.0.1` (or `v2.1.0` if the V4/cancellation features are also ready). Until then, document that `main` is pre-audit and users should build from `fix/audit-patches` or wait for the release tag.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — this is a release-process gap, not a code regression.

### [INFO] Finding A-10: No plaintext-recovery attack found — V2/V3 crypto core is sound for practical threat models
- **Location**: crypto.rs (entire file)
- **Category**: crypto / negative-result
- **Attack**: I attempted the following plaintext-recovery vectors and all failed:
  1. Nonce reuse via counter overflow: requires > 4 PiB file. Guarded in encrypt_file (line 419). Unguarded in encrypt_stream with source_size=None (Finding A-2), but no current caller triggers it.
  2. TOCTOU file-swap in decrypt_file double-open: swapping the file between the magic-read (line 557) and the reopen (line 673) causes the V3 path to process a different file's bytes with the user's key → tag fails → DecryptionFailed. No plaintext leak.
  3. Argon2id timing oracle: all decrypt paths run Argon2id before any tag check (wrong-password and corrupted-file take identical time). The only pre-Argon2id rejections (FileTooSmall, InvalidMagic, FileTooLarge, PassphraseTooShort) leak only info the attacker already knows (file size, magic bytes, password length).
  4. Error-message oracle: all tag failures return identical `CryptoError::DecryptionFailed` ("Wrong password or corrupted file"). No distinguishable error.
  5. Padding oracle: N/A — GCM-SIV is a stream cipher mode, no padding.
  6. Chunk reorder/truncate/extend/substitute: all fail at tag verification (verified in Task 7.4, re-confirmed by reading the decrypt loop).
  7. Downgrade V3→V2 magic swap: dispatcher reroutes to V2 KDF (different HKDF info) → wrong key → tag fails. Verified by test_v3_magic_swap_v3_to_v2_fails (line 1539).
  8. Salt/nonce tampering: changes derived key or AEAD nonce → tag fails. Verified by test_v3_tampered_salt_fails and test_v3_tampered_nonce_fails.
- **Verification**: Read all encrypt/decrypt paths (lines 319-1073). Traced each attack vector through the code. Confirmed GCM-SIV tag verification catches all tampering. Argon2id (256 MiB / 3 iter / 4 lanes) is RFC 9106 compliant and makes offline brute-force expensive. HKDF info strings (`VAULTX02_AES_256_GCM_SIV` vs `VAULTX03_AES_256_GCM_SIV_STREAM`) provide cross-version domain separation (no prefix collision — differ at byte 6).
- **Suggested fix**: None — the crypto core is sound. The findings above (A-2 through A-6) are defense-in-depth and API-safety improvements, not exploitable plaintext-recovery bugs.
- **Confidence**: High
- **Is this a regression from v2.0?**: No

---
Task ID: A2
Agent: Adversarial Crypto Attack Review (v2.1)
Task: Find any way to break Neuron Encrypt v2.1.0's cryptography

Work Log:
- Verified codebase is v2.1: `version = "2.1.0"` in Cargo.toml; 38 matches for MAGIC_V4/cancel_flag/VAULTX04 in crypto.rs, 1 in error.rs.
- Read crypto.rs (2371 lines), error.rs (65 lines), utils.rs (68 lines), cli.rs (842 lines), gui.rs (cancel/batch paths).
- Attack A (V4 AAD correctness): Read build_aad_v4 (line 255-261), all encrypt_next/encrypt_last call sites in encrypt_file (539-543, 562-567, 573-578) and encrypt_stream (1141-1146, 1167-1172, 1177-1182), all decrypt_next/decrypt_last call sites in decrypt_file_streaming_v4 (975-978, 993-996) and decrypt_stream_v4 (1346-1349, 1363-1366). Confirmed AAD is MAGIC_V4 || salt || stream_nonce (31 bytes), computed once per file from the same salt/nonce at encrypt and decrypt. AAD includes MAGIC_V4 (constant). Verified test_v4_tampered_magic_fails (line 2268) covers V4->V3 magic swap.
- Attack B (cancellation races): Read encrypt_file cancel check (528-533), decrypt_file dispatcher check (634-638), decrypt_file_legacy check (687-691), decrypt_file_streaming check (825-830), decrypt_file_streaming_v4 check (957-961). Traced the post-encrypt_last window (562-604) where cancel is not checked. Read gui.rs execute_batch (511-658) for inter-file cancel handling.
- Attack C (downgrade): Traced V4->V3 (derive_key_v3 uses different HKDF info b"VAULTX03_AES_256_GCM_SIV_STREAM" vs V4's b"VAULTX04_AES_256_GCM_SIV_STREAM_AAD"; also V3 uses empty AAD while V4 was sealed with non-empty AAD — double protection). V4->V2 (V2 expects 52-byte header, V4 has 31-byte header → garbage salt/nonce → tag fails). V3->V2 (same as V4->V2). V2->V3 (V3 reads garbage stream_nonce from V2's salt region → wrong key+nonce → tag fails). Dispatcher returns InvalidMagic for unknown magics (line 657, 1229). No UB path.
- Attack D (chunk boundaries): Traced empty file (n=0 → encrypt_last empty), exact-chunk (peek=0 → encrypt_last), 2×chunk (peek=1 → encrypt_next; then n=0 → encrypt_last empty? NO — re-read: second iter reads CHUNK_SIZE, peek=0, encrypt_last). MAX_V4_FILE_SIZE guard at encrypt_file:473 is BEFORE any fallible op. encrypt_stream guard at 1104-1111 is CONDITIONAL on Some(size) — pub API gap.
- Attack E (memory hygiene): derive_key_v4 final_key/intermediate are Zeroizing (231-232). build_aad_v4 returns Vec<u8> (not Zeroizing) — OK, AAD is not secret (magic+salt+nonce are all public). encrypt_file buf is Zeroizing (519). decrypt_file_streaming_v4 buf/last_chunk/pt are Zeroizing (950, 952, 973). salt/stream_nonce on stack are NOT Zeroizing — OK, not secret. peek byte (556) is NOT Zeroizing — carry-over.
- Attack F (Argon2id drift): All three derive_key functions use Params::new(262_144, 3, 4, Some(64)) at lines 194, 214, 233. No other Argon2::new or Params::new calls. No drift.
- Attack G (RNG misuse): All V4 paths use OsRng::fill_bytes (482-483, 1115-1116). tmp_path uses OsRng 8 bytes (363). No thread_rng/SmallRng/StdRng/from_seed/from_entropy found anywhere.
- Attack H (side-channels): All V4 decrypt failures map to DecryptionFailed via .map_err(|_| CryptoError::DecryptionFailed) (979, 997, 1350, 1367). Cancelled returns immediately without Argon2id, but only a local user can trigger Cancelled (no remote oracle). V4 AAD mismatch and key mismatch both produce DecryptionFailed — indistinguishable.
- Attack I (test gaps): No V4 cancel mid-operation test. V4 password-boundary test is indirect (test_v3_password_length_boundary uses encrypt_file which defaults to V4). V4 stream pipe roundtrip exists (test_v4_stream_roundtrip_via_pipe, line 2338). V4 multi-chunk, empty, single-byte, tampered, reordered, extended, magic-swap tests all exist (some indirect via encrypt_file defaulting to V4).
- Attack J (secure_wipe TOCTOU): Read secure_wipe (1031-1088). symlink_metadata (1032) checks no-symlink; OpenOptions::open (1042) follows symlinks. TOCTOU window exists. BUT crypto::secure_wipe is NOT called from anywhere in the codebase (grep confirmed — only gui.rs::secure_wipe_session which is unrelated, clears in-memory GUI state). Pub API only.
- Attack K (peek byte): Line 556 (encrypt_file) and 1162 (encrypt_stream): `let mut peek = [0u8; 1];` — NOT Zeroizing. Carry-over from v2.0, not fixed.

Stage Summary:

### [MEDIUM] Finding A2-1: encrypt_stream pub API skips the 4 PiB counter-wraparound guard when source_size=None
- **Location**: crypto.rs:1103-1111 (encrypt_stream)
- **Category**: crypto-correctness / pub-API
- **Attack**: A library consumer calls `encrypt_stream(reader, writer, password, None, reporter)` with a reader that yields > 4 PiB (2^52 bytes). After 2^32 chunks, the EncryptorBE32 internal 4-byte counter wraps to 0. Chunks N and N+2^32 are then encrypted with the same (key, outer-nonce, counter, flag) triple. For AES-GCM-SIV, the per-message nonce is derived via a PRF over (key, outer-nonce, counter, message). If the plaintext at chunk N equals the plaintext at chunk N+2^32 (e.g., a file of all zeros, or a repeating pattern aligned to 1 MiB), the derived per-message nonces also collide → catastrophic nonce reuse: identical keystream, XOR-of-plaintexts leaks, and tag forgery becomes possible. An attacker who controls the plaintext can deliberately craft a file where chunks N and N+2^32 are identical, then verify keystream reuse from the ciphertext.
- **Verification**: Read encrypt_stream (1092-1198). The guard at 1104-1111 is `if let Some(size) = source_size { if size > MAX_V4_FILE_SIZE { return Err(FileTooLarge{...}); } }`. If `source_size` is `None`, the guard is skipped entirely. The CLI never calls encrypt_stream with None for encrypt mode (cli.rs:697-703 passes `source_size` which is `Some(file_size)` for file input; stdin encrypt is blocked at cli.rs:663-675). So the CLI is safe, but the pub API is unsafe. Compare encrypt_file (line 473-478) which unconditionally enforces `source_len > MAX_V4_FILE_SIZE` using metadata.
- **Suggested fix**: Track bytes encrypted and abort when `chunk_counter` would exceed 2^32, OR require `source_size: u64` (not Option) and enforce unconditionally, OR at minimum add a runtime counter check inside the loop: `chunk_counter += 1; if chunk_counter >= (1u64 << 32) { return Err(FileTooLarge{...}); }` before calling encrypt_next.
- **Confidence**: High (the gap is certain; exploitability requires >4 PiB which is impractical but the pub API should be safe by default)
- **Is this a regression from v2.0?**: Carry-over (partially addressed) — the v2.0 audit (Finding 5-2) flagged that both encrypt_file and encrypt_stream lacked the guard. v2.1 added the guard to encrypt_file (line 473) but made the encrypt_stream guard conditional on Some(size), leaving a residual gap.

### [LOW] Finding A2-2: peek byte buffer not Zeroizing — 1 byte of plaintext lingers on stack at every chunk boundary
- **Location**: crypto.rs:556 (encrypt_file), 1162 (encrypt_stream)
- **Category**: memory / carry-over
- **Attack**: At every chunk boundary (except the last), `let mut peek = [0u8; 1]; let peeked = file.read(&mut peek)?;` reads 1 byte of the NEXT plaintext chunk into a stack variable to determine whether more data follows. This byte is plaintext (read from the source file before encryption). The byte is not zeroed after the `seek(SeekFrom::Current(-1))` at line 589/1191; it persists on the stack until overwritten by a subsequent function call. An attacker with a stack-memory probe (core dump, heartbleed-style read in a co-resident library, cold-boot attack) could recover 1 byte of plaintext per chunk boundary — for a multi-GB file, that is one plaintext byte per 1 MiB, i.e., ~1000 bytes for a 1 GB file.
- **Verification**: Read lines 556-589 (encrypt_file) and 1162-1191 (encrypt_stream). `peek` is `[u8; 1]`, not `Zeroizing<[u8; 1]>`. The byte is plaintext (source file content). The byte is not zeroed after use.
- **Suggested fix**: Replace with `let mut peek = Zeroizing::new([0u8; 1]);` and use `peek.as_mut_slice()` / `&peek[..]`. Or restructure the loop to use `BufReader::fill_buf` to peek without consuming, eliminating the peek-and-seek-back pattern entirely.
- **Confidence**: High
- **Is this a regression from v2.0?**: Carry-over (flagged in v2.0 audit notes as item K; not fixed in v2.1).

### [LOW] Finding A2-3: secure_wipe TOCTOU — symlink swap between metadata check and open (carry-over, dead code internally)
- **Location**: crypto.rs:1032-1042 (secure_wipe)
- **Category**: race / carry-over
- **Attack**: `secure_wipe(path)` calls `fs::symlink_metadata(path)` (line 1032) to verify `path` is a regular file (line 1037: `if !metadata.is_file()` — this correctly rejects symlinks because `symlink_metadata` does not follow them). Then it calls `fs::OpenOptions::new().write(true).open(path)` (line 1042) which FOLLOWS symlinks. An attacker with write access to the directory containing `path` can swap `path` from a regular file to a symlink between the two calls. The `open` then follows the symlink and the 3-pass random overwrite (lines 1045-1057) destroys the symlink's TARGET. If secure_wipe is running as root and the attacker points the symlink at `/etc/passwd`, `/boot/vmlinuz`, or a database file, the attacker can destroy arbitrary root-owned files.
- **Verification**: Read lines 1031-1088. `symlink_metadata` (1032) does not follow symlinks; `is_file()` on its result returns false for symlinks. `OpenOptions::open` (1042) DOES follow symlinks. The gap between the two calls is the TOCTOU window. **Mitigation**: grep confirms `crypto::secure_wipe` is NOT called from anywhere in the codebase (gui.rs::secure_wipe_session is unrelated — clears in-memory GUI state only). So this is a pub-API-only concern; no internal call site is exploitable.
- **Suggested fix**: Open the file with `O_NOFOLLOW` (Unix) via `std::fs::OpenOptions::new().write(true).custom_flags(O_NOFOLLOW)` and verify the fd's metadata matches the path's metadata. Or use `openat(dirfd, basename, O_NOFOLLOW)` to avoid the path-based TOCTOU. Alternatively, deprecate/remove the function if it is dead code.
- **Confidence**: High (TOCTOU is real; exploitability is Low because the function is dead code internally)
- **Is this a regression from v2.0?**: Carry-over (flagged in v2.0 audit notes as item J; not fixed in v2.1).

### [LOW] Finding A2-4: encrypt_file cancel check is skipped after encrypt_last succeeds — user thinks cancel worked but file is silently persisted
- **Location**: crypto.rs:524-604 (encrypt_file loop and post-loop); 562-569 (encrypt_last + break), 593 (sync_all), 602 (persist_temp_file)
- **Category**: race / UX-correctness
- **Attack**: The cancel flag is checked ONLY at the top of the chunk loop (line 528-533). After `encrypt_last` succeeds (line 562-567) and `out.write_all(&ct)` completes (line 568), the loop breaks (line 569). Then `out.sync_all()` (line 593) and `persist_temp_file(&tmp, &dest)` (line 602) run WITHOUT any cancel check. If the user presses Cancel during this window — which can be seconds for a large file's `sync_all` — the encrypted file is still atomically renamed to the destination. The GUI then shows "Operation cancelled by user. No output file was written." (gui.rs:495) but the output file DOES exist on disk. The user is misled into believing no file was created; an attacker who later obtains the persisted ciphertext can brute-force the password offline. The same gap exists in decrypt_file_streaming_v4 (cancel check at 957, but post-loop sync_all at 1002 and persist_temp_file at 1011 are unchecked) — though for decrypt the partial output is plaintext, which is a different concern (partial plaintext leak on cancel).
- **Verification**: Read encrypt_file lines 524-604. The cancel check is at line 528 (top of loop only). After `break` at line 569, no further cancel check before sync_all (593) and persist_temp_file (602). Same pattern in decrypt_file_streaming_v4 (957-1004) and decrypt_file_streaming (825-866).
- **Suggested fix**: Add a cancel check between the loop and persist_temp_file in all four streaming functions: `if let Some(flag) = cancel_flag { if flag.load(Ordering::SeqCst) { let _ = fs::remove_file(&tmp); return Err(CryptoError::Cancelled); } }`. For decrypt, also consider whether partial plaintext should be discarded (it currently is — the tmp is removed — but only if the cancel check fires; if cancel fires after sync_all but before persist_temp_file, the tmp is removed and plaintext is lost, which is the desired behavior).
- **Confidence**: High
- **Is this a regression from v2.0?**: No — new in v2.1 (the cancel_flag was added in v2.1).

### [LOW] Finding A2-5: No V4 cancel mid-operation test — cancel path is untested
- **Location**: crypto.rs test module (lines 1424-2371)
- **Category**: test-gap
- **Attack**: N/A (test gap, not a vuln)
- **Verification**: Grepped the test module for `cancel` and `Cancelled`. Every test passes `None` for cancel_flag. No test exercises the cancel_flag parameter of encrypt_file, decrypt_file, decrypt_file_streaming, decrypt_file_streaming_v4, or decrypt_file_legacy. The cancel-check code paths (lines 528-533, 634-638, 687-691, 825-830, 957-961) are therefore untested. A regression that breaks the cancel check (e.g., removing the `fs::remove_file(&tmp)` cleanup, or changing `Ordering::SeqCst` to `Relaxed`) would ship undetected.
- **Suggested fix**: Add a test that spawns encrypt_file (with a large source file) in a thread with a cancel_flag Arc, sets the flag after a short delay (e.g., 100 ms), joins the thread, and asserts: (1) the result is `Err(CryptoError::Cancelled)`, (2) the destination file does NOT exist, (3) no `.tmp` file lingers in the destination directory. Repeat for decrypt_file_streaming_v4.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — new in v2.1 (cancel_flag was added in v2.1; the test gap is new).

### [INFO] Finding A2-6: encrypt_stream and decrypt_stream do not accept cancel_flag — piped operations cannot be cancelled gracefully
- **Location**: crypto.rs:1092-1098 (encrypt_stream signature), 1202-1208 (decrypt_stream signature)
- **Category**: UX / feature-gap
- **Attack**: N/A (UX gap, not a security issue)
- **Verification**: Read both function signatures. Neither takes a `cancel_flag` parameter. The CLI calls these for pipe mode (cli.rs:697-703, 736-742, 762-768). Once a pipe operation starts, the user cannot cancel it except by killing the process (Ctrl-C / SIGTERM), which leaves a partial output: for encryption, a partial ciphertext with no valid `encrypt_last` chunk (un-decryptable); for decryption, a partial plaintext file (truncated but valid up to the last full chunk). The file-mode paths (encrypt_file, decrypt_file) DO support cancel via the cancel_flag parameter added in v2.1, but the stream paths were not updated.
- **Suggested fix**: Add `cancel_flag: Option<&Arc<AtomicBool>>` to both encrypt_stream and decrypt_stream. Check it at the top of the loop (before each chunk read). On cancel, flush the writer and return `CryptoError::Cancelled`. The CLI would need a SIGINT handler (e.g., via `ctrlc` crate) to set the flag on Ctrl-C.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — the v2.0 versions also lacked cancel_flag; this is a feature gap, not a regression.

### [INFO] Finding A2-7: V4 AAD correctness VERIFIED — no exploit found
- **Location**: crypto.rs:255-261 (build_aad_v4), 494 (encrypt_file), 928 (decrypt_file_streaming_v4), 1126 (encrypt_stream), 1321 (decrypt_stream_v4)
- **Category**: crypto-correctness (positive finding)
- **Attack**: Attempted V4 AAD exploitation: (1) AAD mismatch between encrypt and decrypt — NOT possible, AAD is built from the same salt/nonce at both sides via the same build_aad_v4 function. (2) AAD regenerated with different content per chunk — NOT the case, AAD is computed once per file and reused for every chunk. (3) AAD uses MAGIC_V3 instead of MAGIC_V4 — NOT the case, build_aad_v4 hardcodes MAGIC_V4 (line 257). (4) V4->V3 magic swap to bypass AAD — FAILS because V3 path uses derive_key_v3 (different HKDF info string b"VAULTX03_AES_256_GCM_SIV_STREAM" vs V4's b"VAULTX04_AES_256_GCM_SIV_STREAM_AAD") → different key → tag fails. Additionally, V3 path uses empty AAD while V4 was sealed with non-empty AAD → tag would fail even if keys matched (defense-in-depth). (5) V4->V2 magic swap — FAILS because V2 expects 52-byte header but V4 has 31-byte header → garbage salt/nonce → wrong key → tag fails. Test coverage: test_v4_tampered_magic_fails (line 2268, V4->V3), test_v4_magic_swap_v4_to_v2_fails (line 1966, V4->V2), test_v4_tampered_salt_fails_at_aad (line 2216), test_v4_tampered_nonce_fails_at_aad (line 2243).
- **Verification**: Read build_aad_v4 (255-261): returns `MAGIC_V4 || salt || stream_nonce` (31 bytes). Read all 6 encrypt call sites (encrypt_file: 539-543, 562-567, 573-578; encrypt_stream: 1141-1146, 1167-1172, 1177-1182) — all pass `aad: &aad`. Read all 4 decrypt call sites (decrypt_file_streaming_v4: 975-978, 993-996; decrypt_stream_v4: 1346-1349, 1363-1366) — all pass `aad: &aad`. The AAD is computed once per file (encrypt_file:494, decrypt_file_streaming_v4:928, encrypt_stream:1126, decrypt_stream_v4:1321) from the same salt/nonce. The AAD includes MAGIC_V4 (constant, line 257). Design observation: the AAD uses the CONSTANT MAGIC_V4, not the file's magic bytes — so the AAD does not directly bind the ciphertext to the file's magic. This is safe today because the dispatcher routes by magic and any misroute (V4 file → V3 path) fails at the key-derivation layer. But a future V5 that reuses V4's HKDF info string AND V4's AAD would be confusable with V4. Recommend that future versions use a distinct HKDF info string AND a distinct AAD magic constant.
- **Suggested fix**: None required for v2.1. (For future V5+: use a distinct HKDF info string and a distinct AAD magic constant to maintain cross-version domain separation.)
- **Confidence**: High
- **Is this a regression from v2.0?**: No — new in v2.1; addresses Finding 5-1 from the v2.0 audit (V3 streaming omitted AAD).

### [INFO] Finding A2-8: Argon2id parameter consistency VERIFIED across derive_key, derive_key_v3, derive_key_v4 — no drift
- **Location**: crypto.rs:194 (derive_key), 214 (derive_key_v3), 233 (derive_key_v4)
- **Category**: crypto-correctness (positive finding)
- **Attack**: N/A (positive finding)
- **Verification**: All three functions use `Params::new(262_144, 3, 4, Some(64))` = 256 MiB memory / 3 iterations / 4 lanes / 64-byte output. All use `Algorithm::Argon2id` and `Version::V0x13`. Grepped for other `Argon2::new` or `Params::new` calls — only these three. No drift introduced by V4. The three HKDF info strings (b"VAULTX02_AES_256_GCM_SIV", b"VAULTX03_AES_256_GCM_SIV_STREAM", b"VAULTX04_AES_256_GCM_SIV_STREAM_AAD") are all distinct in both length and content, providing strong cross-version domain separation: the same (password, salt) pair produces three computationally independent AES-256 keys across V2/V3/V4.
- **Suggested fix**: None required.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — consistent with v2.0; V4 added a third identical-params function.

### [INFO] Finding A2-9: RNG misuse check PASSED — all V4 paths use OsRng, no thread_rng/SmallRng introduced
- **Location**: crypto.rs:482-483 (encrypt_file), 1115-1116 (encrypt_stream), 363 (tmp_path), 1051/1070 (secure_wipe), 1437 (test)
- **Category**: crypto-correctness (positive finding)
- **Attack**: N/A (positive finding)
- **Verification**: Grepped for `OsRng`, `thread_rng`, `SmallRng`, `StdRng`, `from_seed`, `from_entropy` across the entire crate. Only `OsRng` is used. Every V4 salt/nonce generation uses `OsRng.fill_bytes(...)` (encrypt_file:482-483, encrypt_stream:1115-1116). tmp_path uses 8-byte OsRng suffix (64 bits entropy, line 363). secure_wipe uses 16-byte OsRng for rename and OsRng for the 3-pass overwrite. Test helper uses OsRng::next_u64 for unique directory names. No V4 path introduced any non-CSPRNG. tmp_path's 64-bit entropy gives birthday-bound collision probability ~N²/2^65 — negligible for any realistic workload.
- **Suggested fix**: None required.
- **Confidence**: High
- **Is this a regression from v2.0?**: No.

### [INFO] Finding A2-10: Error side-channels consistent — V4 AAD mismatch and key mismatch both map to DecryptionFailed; Cancelled is local-only (no remote oracle)
- **Location**: crypto.rs:979, 997 (decrypt_file_streaming_v4), 1350, 1367 (decrypt_stream_v4); error.rs:60-61 (Cancelled variant)
- **Category**: side-channel (positive finding)
- **Attack**: Attempted to distinguish "wrong password" (key mismatch) from "tampered AAD" (AAD mismatch) from "tampered ciphertext" (tag mismatch) via error type or timing. All three produce the identical `CryptoError::DecryptionFailed` ("Wrong password or corrupted file") because every decrypt failure path uses `.map_err(|_| CryptoError::DecryptionFailed)?` (lines 979, 997, 1350, 1367). The underlying AEAD error is discarded. Timing: all decrypt paths run Argon2id (the slow ~0.5-1s step) BEFORE any tag check, so wrong-password and corrupted-file take identical wall-clock time. The Cancelled variant returns immediately WITHOUT running Argon2id, creating a timing difference — but Cancelled can only be triggered by the local user pressing the Cancel button (gui.rs:1485), not by a remote attacker. So there is no remote timing oracle. Pre-Argon2id rejections (FileTooSmall at 908, InvalidMagic at 657/1229, FileTooLarge at 473/1106, PassphraseTooShort at 463/1099) leak only information the attacker already knows (file size, magic bytes, password length).
- **Suggested fix**: None required.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — consistent with v2.0 (Finding 5-13); V4 preserves the property.

### [INFO] Finding A2-11: No plaintext-recovery attack found against V4 — crypto core is sound for practical threat models
- **Location**: crypto.rs (entire file)
- **Category**: crypto / negative-result
- **Attack**: Attempted the following plaintext-recovery vectors against V4 and all failed:
  1. V4 AAD forgery: AAD is MAGIC_V4 || salt || stream_nonce, authenticated on every chunk. Tampering any field → tag fails (verified by tests at lines 2216, 2243, 2268).
  2. V4 nonce reuse via counter overflow: requires > 4 PiB. Guarded in encrypt_file (line 473, unconditional). Unguarded in encrypt_stream with source_size=None (Finding A2-1), but no current caller triggers it.
  3. V4 chunk reorder/truncate/extend/substitute: all fail at BE32 flag/counter + GCM-SIV tag verification (verified by tests at lines 1853, 1992, 2037, 1939 — all use encrypt_file which defaults to V4).
  4. V4 downgrade to V3/V2: dispatcher routes by magic; V3 path uses different HKDF info + empty AAD → tag fails; V2 path misreads 31-byte header as 52-byte → garbage salt → tag fails (verified by tests at 2268, 1966).
  5. V4 wrong-password: Argon2id runs (slow), then tag fails → DecryptionFailed, indistinguishable from corrupted-file (verified by test at 2318).
  6. V4 empty/single-byte/exact-chunk/chunk±1: all roundtrip correctly (verified by tests at 2297, 1835, 1678, 2083, 2102).
  7. V4 stream pipe roundtrip: encrypt_stream → decrypt_stream produces original bytes (verified by test at 2338).
- **Verification**: Read all V4 encrypt/decrypt paths (encrypt_file 455-605, decrypt_file_streaming_v4 891-1025, encrypt_stream 1092-1198, decrypt_stream_v4 1302-1377). Traced each attack through the code. Confirmed AES-256-GCM-SIV tag verification + BE32 counter/flag binding + AAD header authentication catches all tampering. Argon2id (256 MiB / 3 iter / 4 lanes) makes offline brute-force expensive. HKDF info strings provide cross-version domain separation.
- **Suggested fix**: None — the V4 crypto core is sound. The findings above (A2-1 through A2-5) are defense-in-depth, API-safety, UX, and test-coverage improvements, not exploitable plaintext-recovery bugs.
- **Confidence**: High
- **Is this a regression from v2.0?**: No — V4 is a strict improvement over V3 (closes the AAD gap from Finding 5-1).

---
Task ID: C2
Agent: Second-Pass Code Audit (v2.1)
Task: Find bugs introduced by v2.1 changes

Work Log:
- Verified codebase is v2.1: `version = "2.1.0"` in neuron-encrypt/Cargo.toml; 32 matches for MAGIC_V4/cancel_flag/VAULTX04 in crypto.rs.
- Read prior worklog Tasks 5, 6, 7, A, A2 (924 lines) to avoid repeating findings.
- Read crypto.rs (2371 lines) — V4 paths (encrypt_file 455-605, decrypt_file_streaming_v4 891-1025, encrypt_stream 1092-1198, decrypt_stream_v4 1302-1377), cancel_flag plumbing (528-533, 957-961), build_aad_v4 (255-261), derive_key_v4 (230-244).
- Read error.rs (65 lines) — Cancelled variant at line 60-61, PassphraseTooShort message at line 54.
- Read gui.rs (2044 lines) — execute() cancel_for_thread cloning (455, 471, 480), execute_batch() cancel passing (558, 620, 629), draw_processing() Cancel button (1484-1488), Cancelled→Done mapping (491-498), message handler (1936-1955), batch hash computation (635-639), Advanced CollapsingHeader (1233-1301), Details CollapsingHeader (1558-1577), scramble_text removal (157, 1994), rand_core removal (18), version stamp removal (2037-2039).
- Read cli.rs (842 lines) — read_password returns Zeroizing<Vec<u8>> (109-150), .as_slice() call sites (533, 542, 700, 739, 765), "bytes" message (425), None for cancel_flag (535, 544).
- Read android/neuron-encrypt-jni/src/lib.rs (385 lines) — CancelableReader (21-62), map_error Cancelled arm (116), Io(Interrupted) arm (90-92), safety docs (295-313, 347-353), panic::catch_unwind (325-345, 365-385).
- Read .github/workflows/android.yml (134 lines) — lint-and-test job (17-68), clippy JNI step (54-56), build job (70-135).
- Read .github/workflows/android-release.yml (191 lines) — sign step with debug fallback (131-155), APK artifact upload (173-180), release attachment (182-191).
- Read docs/index.html (284 lines) — hero stats (50-55), cancel claim (86), audit count claim (218), worklog.md link (218).
- Read README.md (675 lines) — What's New in 2.1 (29-42), cancel latency claim (32), Argon2id output claim (100), broken links to SECURITY_AUDIT.md/CHANGELOG.md (44).
- Read android/app/build.gradle.kts — minSdk=24, versionName="2.1.0".
- Read MainActivity.kt (136 lines) — getParcelableExtra guard for API 33+ (102-111), fallback for API 24-32 (104-110).
- Read values-v27/styles.xml and values/styles.xml — windowLightNavigationBar overlay correct.
- Read AndroidManifest.xml — allowBackup=false, fullBackupContent=false.
- Verified Cargo.lock versions: neuron-encrypt 2.1.0, neuron-encrypt-jni 2.1.0.
- Verified no remaining scramble_text/rand_core/CARGO_PKG_VERSION/"Use at least" references in gui.rs (grep confirmed — only comments remain).
- Verified README headings for #build-from-source and #cli-usage anchors — both exist, website links are valid.
- Verified worklog.md, SECURITY_AUDIT.md, CHANGELOG.md do NOT exist in the repo (ls confirmed).

Stage Summary:

### [MEDIUM] Finding C2-1: Batch encrypt mode hashes the SOURCE (plaintext) file, contradicting the P2-4 design rationale that says "always hash the OUTPUT file to avoid leaking a plaintext-hash verifier"
- **Location**: gui.rs:635-639 (execute_batch hash computation)
- **Category**: gui-bug / info-leak
- **Description**: In single-file encrypt mode, `execute()` at line 488 calls `compute_sha256(&dest)` (ciphertext hash) with the P2-4 comment: "always hash the OUTPUT file (ciphertext on encrypt, plaintext on decrypt). Avoids leaking a plaintext-hash verifier via screenshots." But `execute_batch()` at lines 635-639 does the OPPOSITE for encrypt mode: `let hash = if mode == Mode::Decrypt { compute_sha256(&out_path) } else { compute_sha256(src) };` — for Encrypt, it hashes `src` (the plaintext input), not `&out_path` (the ciphertext output). The batch results UI at lines 1876-1888 then displays the first 16 hex chars (64 bits) of this plaintext hash next to each encrypted file name. An attacker with a screenshot of the batch results + access to candidate plaintexts can compute SHA-256 of each candidate and compare the first 16 hex chars — a 64-bit plaintext verifier. The single-file mode was fixed in P2-4 but batch mode was overlooked.
- **Verification**: Read gui.rs:488 (single-file: `compute_sha256(&dest)`) vs gui.rs:635-639 (batch: `compute_sha256(src)` for Encrypt). Read gui.rs:1876-1888 (batch results display `&hash[..16]`). The P2-4 comment at line 486-487 explicitly states the rationale that batch mode violates.
- **Suggested fix**: Change line 638 from `compute_sha256(src)` to `compute_sha256(&out_path)` so batch encrypt mode hashes the ciphertext output, matching single-file mode and the P2-4 rationale.
- **Confidence**: High

### [MEDIUM] Finding C2-2: docs/index.html links to worklog.md on GitHub, but worklog.md is not in the repo — 404
- **Location**: docs/index.html:218
- **Category**: website-bug / broken-link
- **Description**: The website's Security section says "Full audit report: 44 findings..." and links to `https://gitlab.com/theredhacker0345/neuron-encrypt/-/blob/main/SECURITY_AUDIT.md`. But `worklog.md` does not exist in the repo (verified via `ls` — only README.md, SECURITY_DEFER.md, LICENSE exist at repo root). The actual worklog.md lives at `/home/z/my-project/worklog.md` (outside the repo). Users who click "Read the audit ↗" get a GitHub 404 page.
- **Verification**: `ls /home/z/my-project/Neuron-Encrypt/worklog.md` → "No such file or directory". `find /home/z/my-project/Neuron-Encrypt -maxdepth 2 -name "worklog*"` → no results. docs/index.html:218 contains the broken link.
- **Suggested fix**: Either (a) commit worklog.md to the repo at the linked path, or (b) change the link to point to SECURITY_DEFER.md (which does exist), or (c) remove the link and host the audit report elsewhere.
- **Confidence**: High

### [MEDIUM] Finding C2-3: README.md links to SECURITY_AUDIT.md and CHANGELOG.md, neither of which exists in the repo — 404
- **Location**: README.md:44
- **Category**: docs-bug / broken-link
- **Description**: README.md line 44 says "See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the full audit report and [CHANGELOG.md](CHANGELOG.md) for a complete change history." Neither file exists in the repo (verified via `ls` — only README.md, SECURITY_DEFER.md, LICENSE exist at repo root). Users who click these links get a GitHub 404 page. The repo has SECURITY_DEFER.md but not SECURITY_AUDIT.md — likely a rename that wasn't propagated to the README.
- **Verification**: `ls /home/z/my-project/Neuron-Encrypt/SECURITY_AUDIT.md` → "No such file or directory". `ls /home/z/my-project/Neuron-Encrypt/CHANGELOG.md` → "No such file or directory". README.md:44 contains both broken links.
- **Suggested fix**: Either (a) create SECURITY_AUDIT.md and CHANGELOG.md, or (b) update the links to point to SECURITY_DEFER.md (the file that exists) and remove the CHANGELOG.md reference, or (c) link to the website's security section instead.
- **Confidence**: High

### [LOW] Finding C2-4: error.rs PassphraseTooShort message says "characters" but the crypto check uses byte length — inconsistent with CLI/JNI "bytes" messaging after the v2.1 binary-password change
- **Location**: error.rs:54
- **Category**: docs-bug / inconsistency
- **Description**: The v2.1 change to binary password files (Vec<u8> instead of String) updated the CLI message to "Passphrase too short (minimum {} bytes)." (cli.rs:425) and the JNI message to "Passphrase must be at least {min} bytes." (lib.rs:99). But the underlying `CryptoError::PassphraseTooShort` error message in error.rs:54 still says "Passphrase too short (minimum {0} characters required)". The crypto check at crypto.rs:463, 1099 uses `password.len()` (byte length), so "characters" is technically wrong for the crypto error. The GUI also says "characters" (gui.rs:404, 517) but that's consistent with the GUI's `chars().count()` check. The inconsistency is between the crypto error message ("characters") and the CLI/JNI messages ("bytes"), and the crypto error is the one that's semantically wrong.
- **Verification**: Read error.rs:54 ("characters required"). Read cli.rs:425 ("bytes"). Read lib.rs:99 ("bytes"). Read crypto.rs:463, 1099 (`password.len() < MIN_PASSWORD_LEN` — byte length). The crypto error message uses "characters" but the check is byte-based.
- **Suggested fix**: Change error.rs:54 from `"(minimum {0} characters required)"` to `"(minimum {0} bytes required)"` to match the byte-based check and the CLI/JNI messaging.
- **Confidence**: High

### [LOW] Finding C2-5: docs/index.html "under 50 ms" cancel claim is misleading — actual latency includes non-cancellable Argon2id (~1s) and post-encrypt_last sync_all
- **Location**: docs/index.html:86
- **Category**: website-bug / misleading-claim
- **Description**: The website says "Started encrypting the wrong file? Hit Cancel. The .tmp file is cleaned up and you're back to a clean state in under 50 ms." This is misleading. The actual cancel latency depends on when the user clicks Cancel: (1) During Argon2id key derivation (~500-1000 ms): the cancel flag is checked only at the top of the chunk loop (crypto.rs:528), which runs AFTER Argon2id completes — so the user waits ~1s with no cancel effect. (2) During a 1 MB chunk: cancel takes effect after the current chunk completes (1-50 ms on SSD, 10-100 ms on HDD). (3) After encrypt_last succeeds but before persist_temp_file (A2-4 finding): cancel is NOT checked, so the file is silently persisted. The GUI itself honestly tells the user "Cancel takes effect after the current 1 MB chunk completes." (gui.rs:1492) — the website contradicts the GUI.
- **Verification**: Read crypto.rs:528-533 (cancel check at top of loop only, AFTER Argon2id at line 487). Read gui.rs:1492 (honest "after the current 1 MB chunk" message). Read docs/index.html:86 ("under 50 ms" claim). The website claim is best-case only.
- **Suggested fix**: Change "under 50 ms" to "after the current 1 MB chunk completes (typically under 50 ms on SSD, longer on slow disks)" or simply "within a few seconds" to set accurate expectations.
- **Confidence**: High

### [LOW] Finding C2-6: README.md "~50 ms latency" cancel claim — same misleading claim as C2-5
- **Location**: README.md:32
- **Category**: docs-bug / misleading-claim
- **Description**: README.md line 32 says "The Cancel button polls a flag at every 1 MB chunk boundary (~50 ms latency)". Same issue as C2-5: the ~50 ms is best-case for a single chunk boundary on fast SSD. The actual latency includes the non-cancellable Argon2id phase (~1s) if the user clicks Cancel during key derivation, and the post-encrypt_last sync_all + persist_temp_file window (A2-4) where cancel is not checked at all.
- **Verification**: Read README.md:32. Read crypto.rs:528-533 (cancel check location). The "~50 ms" claim is best-case.
- **Suggested fix**: Change "~50 ms latency" to "after the current 1 MB chunk boundary" and note that Argon2id key derivation (~1s) cannot be interrupted.
- **Confidence**: High

### [LOW] Finding C2-7: README.md "Output: 32 bytes" for Argon2id is inaccurate — code uses Some(64) (64-byte output)
- **Location**: README.md:100
- **Category**: docs-bug / inaccuracy
- **Description**: README.md line 100 in the "Cryptographic Parameters" block says "Output: 32 bytes" for Argon2id. But the actual code at crypto.rs:194, 214, 233 uses `Params::new(262_144, 3, 4, Some(64))` — the Argon2id output is 64 bytes, not 32. The 64-byte output is fed into HKDF-SHA512, which expands it to 32 bytes for the AES-256 key. So "Output: 32 bytes" conflates the Argon2id output with the final AES key length. This was likely correct in an earlier version where Argon2id produced 32 bytes directly, but the v2.0/v2.1 code uses 64 bytes + HKDF.
- **Verification**: Read README.md:96-101 ("Output: 32 bytes"). Read crypto.rs:194 (`Params::new(262_144, 3, 4, Some(64))`). Read crypto.rs:191 (`let mut final_key = Zeroizing::new(vec![0u8; 32])`). The Argon2id output is 64 bytes (intermediate), HKDF expands to 32 bytes (final_key).
- **Suggested fix**: Change "Output: 32 bytes" to "Output: 64 bytes (→ HKDF-SHA512 → 32-byte AES key)" or add a separate line for the HKDF step.
- **Confidence**: High

### [LOW] Finding C2-8: GUI Cancelled→Done message is never displayed — message handler wipes the session instead of showing the calm message
- **Location**: gui.rs:491-498 (Cancelled→Done mapping) vs gui.rs:1936-1946 (message handler)
- **Category**: gui-bug / UX-inconsistency
- **Description**: When the crypto thread receives a Cancel signal, it sends `GuiMsg::Done("Operation cancelled by user. No output file was written.", None)` (gui.rs:494-497). The comment at line 492-493 says this is "so the user doesn't see a scary 'Error' screen." But the message handler at line 1936-1946 checks `if self.cancel_flag.load(Ordering::SeqCst)` and calls `secure_wipe_session(ctx)` — which resets `self.status = None` and `self.flow = AppFlow::FileDrop`. The calm "Operation cancelled" message is DISCARDED and never displayed. The user clicks Cancel and sees the FileDrop screen with no explanation of what happened. This defeats the stated purpose of the Cancelled→Done mapping.
- **Verification**: Read gui.rs:491-498 (Done message construction). Read gui.rs:1936-1946 (message handler — if cancel_flag is true, secure_wipe_session is called, skipping the else-branch that would set self.status and self.flow=Success). Read gui.rs:276-304 (secure_wipe_session resets status to None and flow to FileDrop).
- **Suggested fix**: Either (a) in the message handler, show the cancel message before wiping: `self.status = Some(message); self.flow = AppFlow::Success;` instead of `secure_wipe_session`, OR (b) if the wipe-to-FileDrop behavior is intentional, remove the dead "Operation cancelled by user" message construction at line 494-497 and just send `GuiMsg::Done(String::new(), None)` to signal completion. Option (a) is better UX — the user gets confirmation that cancel worked.
- **Confidence**: High

### [LOW] Finding C2-9: android-release.yml sign step uses $ANDROID_HOME/debug.keystore (non-standard path) — fallback catches it but produces debug APK at a different path
- **Location**: .github/workflows/android-release.yml:145
- **Category**: ci-bug / fragile-fallback
- **Description**: The sign step falls back to `$ANDROID_HOME/debug.keystore` when no upload keystore secret is configured. The standard Android debug keystore location is `~/.android/debug.keystore` (created on-demand by the SDK tools), NOT `$ANDROID_HOME/debug.keystore`. On a fresh GitHub Actions runner, `$ANDROID_HOME/debug.keystore` may not exist. The `|| ./gradlew assembleDebug` fallback at the end of line 145 catches this failure and produces a debug APK at `app/build/outputs/apk/debug/app-debug.apk` (instead of the release APK at `app/build/outputs/apk/release/`). The subsequent "Locate built APK" step at line 160 uses `find ... -name "*.apk" | head -1` which picks up whichever APK exists — so the workflow doesn't fail, but the result is a debug-signed APK masquerading as a release APK. This is fragile and the fallback masks the real issue.
- **Verification**: Read android-release.yml:143-155. Line 145 references `$ANDROID_HOME/debug.keystore`. The `|| ./gradlew assembleDebug` fallback produces a different APK path. Read line 160 (`find ... | head -1` — picks any APK). The standard debug keystore path is `~/.android/debug.keystore`, not `$ANDROID_HOME/debug.keystore`.
- **Suggested fix**: Change `$ANDROID_HOME/debug.keystore` to `$HOME/.android/debug.keystore` (the standard path). Or pre-create the debug keystore with `keytool -genkey` before the sign step. Or remove the debug-signing fallback entirely and fail loudly if no upload keystore is configured — a debug-signed "release" APK is misleading.
- **Confidence**: Medium (the fallback may work on GitHub runners if the SDK pre-creates the keystore, but the path is non-standard and the fallback masks the issue)

### [INFO] Finding C2-10: JNI map_error CryptoError::Cancelled arm is unreachable — encrypt_stream/decrypt_stream don't take cancel_flag
- **Location**: android/neuron-encrypt-jni/src/lib.rs:116
- **Category**: jni-bug / dead-code
- **Description**: The `map_error` function at line 116 has an arm for `CryptoError::Cancelled => (1, "Cancelled".to_owned())`. But the JNI layer calls `encrypt_stream` and `decrypt_stream` (lib.rs:200-206, 277-283), neither of which accepts a `cancel_flag` parameter. The Android cancel mechanism is via `CancelableReader` (lib.rs:21-62) which returns `io::ErrorKind::Interrupted`, caught by the `CryptoError::Io(ref io_err) if io_err.kind() == io::ErrorKind::Interrupted` arm at line 90-92. So `encrypt_stream`/`decrypt_stream` can never return `CryptoError::Cancelled` — the arm at line 116 is defensive but unreachable. Not a bug, but dead code that could confuse future maintainers.
- **Verification**: Read lib.rs:200-206 (encrypt_stream call — no cancel_flag param). Read crypto.rs:1092-1098 (encrypt_stream signature — no cancel_flag). Read lib.rs:90-92 (Io(Interrupted) arm — the actual cancel path). Read lib.rs:116 (Cancelled arm — unreachable from JNI paths).
- **Suggested fix**: Add a comment noting the arm is defensive/future-proofing, or remove it if encrypt_stream/decrypt_stream are never expected to take cancel_flag. Low priority.
- **Confidence**: High

### [INFO] Finding C2-11: android.yml clippy step builds JNI crate for Linux host, not Android target — Android-specific cfg gates not exercised
- **Location**: .github/workflows/android.yml:54-56
- **Category**: ci-bug / coverage-gap
- **Description**: The "clippy (JNI)" step at line 55-56 runs `cargo clippy --all-targets` without specifying a `--target`. This builds the JNI crate for the Linux host triple. The comment at line 54 acknowledges this ("no target specified so it builds for host"). The JNI crate uses `std::os::fd` (Unix-only) which works on Linux. However, the actual Android build (in the `build` job at line 108-113 via `build-rust.sh`) cross-compiles for `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, and `i686-linux-android`. Any Android-specific `cfg(target_os = "android")` gates or Android-only dependencies would NOT be exercised by the host clippy step. The clippy step catches host-compilable issues but misses Android-specific issues.
- **Verification**: Read android.yml:54-56 (clippy without --target). Read android.yml:94 (Rust targets include 4 Android triples). The host clippy build does not exercise Android cfg gates. The comment at line 54 acknowledges this is host-only.
- **Suggested fix**: Add a separate clippy step with `--target aarch64-linux-android` (the most common Android ABI) to catch Android-specific issues. Or run `cargo ndk clippy` which handles the cross-compilation. Low priority — the current step still catches most issues.
- **Confidence**: High

### [INFO] Finding C2-12: V4 AAD correctness VERIFIED — no V4 path bug found (positive finding)
- **Location**: crypto.rs:255-261 (build_aad_v4), 494/928/1126/1321 (AAD computation), all encrypt/decrypt call sites
- **Category**: v4-bug (negative result)
- **Description**: Traced all V4 AAD paths: (1) `build_aad_v4` (line 255-261) returns `MAGIC_V4 || salt || stream_nonce` (31 bytes), computed once per file from the same salt/nonce at encrypt and decrypt. (2) `encrypt_file` V4 path: empty-file case (n=0) at line 536-546 correctly calls `encrypt_last` with `Payload{msg: &[][..], aad: &aad}` — AAD is passed even for the empty last chunk. Exact-chunk case (peek=0) at line 559-569 correctly calls `encrypt_last` with AAD. Multi-chunk case at line 570-590 correctly calls `encrypt_next` with AAD. (3) `encrypt_stream` V4 path: identical structure, AAD passed at lines 1141-1146, 1167-1172, 1177-1182. (4) `decrypt_file_streaming_v4`: delayed-by-one `last_chunk` pattern, AAD passed to `decrypt_next` (975-978) and `decrypt_last` (993-996). (5) `decrypt_stream_v4`: same delayed-by-one pattern, AAD passed at 1346-1349 and 1363-1366. All AAD values are identical within a file and computed from the same header bytes. No last_chunk delay-by-one bug, no missing-AAD call site, no empty-file edge case bug.
- **Verification**: Read all V4 encrypt/decrypt paths in full (encrypt_file 455-605, decrypt_file_streaming_v4 891-1025, encrypt_stream 1092-1198, decrypt_stream_v4 1302-1377). Traced AAD construction and usage at every call site. Confirmed AAD = MAGIC_V4 || salt || stream_nonce (31 bytes) at all 10 AEAD call sites (6 encrypt, 4 decrypt). The empty-file case (n=0 → encrypt_last empty) correctly passes AAD at lines 541 and 1144.
- **Suggested fix**: None required — V4 AAD is correct.
- **Confidence**: High

---
Task ID: B3
Agent: Quick Fuzzing Test
Task: Verify V4 file is robust to tampering

Work Log:
- Verified MAGIC_V4 present in crypto.rs (14 matches, ≥5 required)
- Installed Rust toolchain (rustup, stable 1.97.1) — no system cargo available
- Built `neuron-encrypt-cli` v2.1.0 in release mode (LTO disabled via env override to fit sandbox time budget; binary at `target/release/neuron-encrypt-cli`, 1.07 MB, stripped)
- Wrote `/home/z/my-project/scripts/attack_v4_round.py`:
  - Encrypts 1760-byte plaintext with password "testpassword123" via CLI (NEURON_PASSWORD env var)
  - Verifies output starts with VAULTX04 magic
  - Performs sanity round-trip decrypt
  - Builds 6 tampered copies (flip salt @8, flip nonce @24, magic V4→V3 @7, flip first body byte @31, truncate to 31B header, append 100B garbage)
  - Decrypts each tampered copy, records exit code + stderr
  - Uniqueness check: 5 encryptions of identical plaintext/password, asserts all 5 ciphertexts differ (random salt+nonce per file)
- Ran 6 tamper attacks + 1 uniqueness check; all passed

Stage Summary:

TAMPER ATTACK RESULTS (all 6 attacks correctly rejected by the V4 decryptor):

| Attack                   | Expected | Actual exit | Actual stderr                                  | Result |
|--------------------------|----------|-------------|------------------------------------------------|--------|
| Flip salt                | fail     | 3           | "Wrong passphrase or corrupted file."          | PASS   |
| Flip nonce               | fail     | 3           | "Wrong passphrase or corrupted file."          | PASS   |
| Flip magic V4→V3         | fail     | 3           | "Wrong passphrase or corrupted file."          | PASS   |
| Flip first body byte     | fail     | 3           | "Wrong passphrase or corrupted file."          | PASS   |
| Truncate to header (31B) | fail     | 1           | "File too small to be a valid VAULTX02 encr…"  | PASS   |
| Append 100B garbage      | fail     | 3           | "Wrong passphrase or corrupted file."          | PASS   |

UNIQUENESS CHECK:
- 5/5 distinct ciphertext files (expected 5)
- 5/5 distinct salt+nonce regions (bytes 8..31, expected 5)
- Per-file salt+nonce (hex of bytes 8..31) all unique — random OsRng output per encryption confirmed

CONCLUSION:
- V4 tamper-resistance: PASS (6/6 attacks detected)
- Per-file randomness: PASS (5/5 unique ciphertexts)
- The V4 AAD design (MAGIC_V4 || salt || stream_nonce authenticated on every AEAD chunk) correctly causes header-byte flips (salt, nonce, magic) to be detected at the AEAD layer with the standard "Wrong passphrase or corrupted file" error — the same error body-byte flips and append-garbage produce. Truncation to header-only is caught earlier at the file-size validation gate (exit code 1).
- Minor cosmetic note (not a security issue): the truncation error message says "VAULTX02 encrypted file" instead of "VAULTX04" — the size-check error string was not updated for V4. Functionally harmless (file is still correctly rejected), but cosmetically misleading. Suggest updating the error string to "VAULTX04" (or "VAULTX02/03/04") in a future patch.
- No vulnerabilities found. V4 is robust to all 6 tested tamper classes.
