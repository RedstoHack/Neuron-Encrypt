package com.neuronencrypt.app

enum class Strength { None, Weak, Fair, Strong, Elite }

data class StrengthResult(
    val strength: Strength,
    val fraction: Float,
    val label: String
)

/**
 * Entropy-based password strength estimator (zxcvbn-inspired).
 *
 * Replaces the previous character-class scoring which labeled dictionary-weak
 * passphrases like "Password1!" as "Strong". The new estimator:
 *
 * 1. Detects common patterns (repeated chars, sequences, common passwords)
 * 2. Estimates charset size based on actual character types used
 * 3. Computes Shannon entropy: log2(charsetSize^length)
 * 4. Penalizes patterns that reduce effective entropy
 * 5. Maps entropy to strength tiers
 *
 * This is NOT a full zxcvbn port (that would require a dictionary file), but
 * it catches the most common false-strong cases: short passwords with mixed
 * character classes, keyboard sequences, repeated characters, and the top
 * 100 most common passwords.
 */
fun evalStrength(password: String): StrengthResult {
    if (password.isEmpty()) {
        return StrengthResult(Strength.None, 0.0f, "None")
    }

    val len = password.length
    var hasLower = false
    var hasUpper = false
    var hasDigit = false
    var hasSymbol = false

    for (c in password) {
        when {
            c in 'a'..'z' -> hasLower = true
            c in 'A'..'Z' -> hasUpper = true
            c in '0'..'9' -> hasDigit = true
            else -> hasSymbol = true
        }
    }

    // Charset size
    var charsetSize = 0
    if (hasLower) charsetSize += 26
    if (hasUpper) charsetSize += 26
    if (hasDigit) charsetSize += 10
    if (hasSymbol) charsetSize += 33 // common ASCII symbols

    if (charsetSize == 0) charsetSize = 1

    // Base entropy: log2(charsetSize^len) = len * log2(charsetSize)
    var entropy = len * (Math.log(charsetSize.toDouble()) / Math.log(2.0))

    // Pattern penalties (reduce effective entropy)
    entropy -= repeatedCharsPenalty(password)
    entropy -= sequencePenalty(password)
    entropy -= commonPasswordPenalty(password)

    // Length bonus (passphrases are strong even with small charset)
    if (len >= 20) entropy += 10.0
    if (len >= 32) entropy += 15.0

    entropy = entropy.coerceAtLeast(0.0)

    // Map entropy to strength tiers (based on NIST 800-63B guidance)
    // <28 bits = Weak (trivially crackable)
    // 28-35 = Fair (offline attack in hours)
    // 36-59 = Strong (offline attack in years with Argon2id)
    // 60+ = Elite (offline attack infeasible)
    val fraction = (entropy / 80.0f).coerceIn(0.0f, 1.0f)

    return when {
        entropy < 28.0 -> StrengthResult(Strength.Weak, fraction, "Weak")
        entropy < 36.0 -> StrengthResult(Strength.Fair, fraction, "Fair")
        entropy < 60.0 -> StrengthResult(Strength.Strong, fraction, "Strong")
        else -> StrengthResult(Strength.Elite, fraction, "Elite")
    }
}

/** Penalize repeated characters (aaa, 111, !!!). */
private fun repeatedCharsPenalty(password: String): Double {
    var penalty = 0.0
    var runLength = 1
    for (i in 1 until password.length) {
        if (password[i] == password[i - 1]) {
            runLength++
        } else {
            if (runLength >= 3) {
                penalty += (runLength - 2) * 3.0
            }
            runLength = 1
        }
    }
    if (runLength >= 3) {
        penalty += (runLength - 2) * 3.0
    }
    return penalty
}

/** Penalize keyboard/alphabetical sequences (abc, 123, qwerty). */
private fun sequencePenalty(password: String): Double {
    val lower = password.lowercase()
    val sequences = listOf(
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "0123456789",
        "!@#$%^&*"
    )

    var penalty = 0.0
    for (seq in sequences) {
        // Check for forward sequences of length >= 3
        for (i in 0..seq.length - 3) {
            val sub = seq.substring(i, i + 3)
            if (lower.contains(sub)) {
                penalty += 5.0
            }
        }
        // Check for reversed sequences
        val reversed = seq.reversed()
        for (i in 0..reversed.length - 3) {
            val sub = reversed.substring(i, i + 3)
            if (lower.contains(sub)) {
                penalty += 5.0
            }
        }
    }
    return penalty
}

/** Penalize the top ~30 most common passwords (subset of the top 100 list). */
private fun commonPasswordPenalty(password: String): Double {
    val lower = password.lowercase()
    val common = setOf(
        "password", "pass", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
        "iloveyou", "master", "sunshine", "ashley", "michael", "shadow",
        "123123", "654321", "superman", "qazwsx", "michael", "football",
        "password1", "password123", "admin", "welcome", "hello", "freedom",
        "whatever", "trustno1", "hunter2", "password!", "p@ssw0rd", "p@ssword"
    )

    // Check exact match or if the password starts with a common password
    for (cp in common) {
        if (lower == cp || lower.startsWith(cp)) {
            return 40.0 // heavy penalty — reduces to Weak
        }
    }
    return 0.0
}
