// SPDX-License-Identifier: GPL-3.0-or-later
//! ISO 8601 timestamp helpers with no external crate dependency.
//!
//! Exposed at the library level so every Gitway binary (the main CLI plus
//! the `gitway-keygen` and `gitway-add` shims) can emit the same timestamp
//! format in structured JSON output and single-line diagnostic records.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current UTC time as an ISO 8601 string (e.g. `2026-04-12T14:30:00Z`).
#[must_use]
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_secs_to_iso8601(secs)
}

/// Converts a Unix timestamp (seconds since 1970-01-01T00:00:00Z) to ISO 8601.
///
/// Uses the civil calendar algorithm from
/// <https://howardhinnant.github.io/date_algorithms.html> — no external crate
/// required.  Valid for any date representable as a positive `u64` epoch.
#[must_use]
#[expect(
    clippy::similar_names,
    reason = "doe/doy are the standard abbreviations in the Hinnant date algorithm"
)]
pub fn epoch_secs_to_iso8601(secs: u64) -> String {
    let sec = secs % 60;
    let mins = secs / 60;
    let min = mins % 60;
    let hours = mins / 60;
    let hour = hours % 24;
    let days = hours / 24;

    // Civil date from days-since-epoch.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::epoch_secs_to_iso8601;

    #[test]
    fn epoch_secs_to_iso8601_unix_epoch() {
        assert_eq!(epoch_secs_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn epoch_secs_to_iso8601_known_date() {
        // 2026-04-12T00:00:00Z — verified manually.
        // Days from epoch: 56 years × 365 + 14 leap days + 101 days into 2026
        // = 20440 + 14 + 101 = 20555 days × 86400 s/day = 1_775_952_000
        assert_eq!(epoch_secs_to_iso8601(1_775_952_000), "2026-04-12T00:00:00Z");
    }
}
