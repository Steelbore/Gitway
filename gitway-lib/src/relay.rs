// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Bidirectional stdin/stdout relay over an SSH exec channel (FR-14 through FR-17).
//!
//! The relay spawns a background task that copies `tokio::io::stdin()` into the
//! channel's write half, and runs a read loop on the current task that copies
//! channel data to `tokio::io::stdout()` and `tokio::io::stderr()`.
//!
//! When the remote process exits, its exit code is returned.  Exit-via-signal
//! is translated to `128 + signal_number`, matching OpenSSH convention (FR-17).

use tokio::io::AsyncWriteExt as _;

use russh::client::Msg;
use russh::{Channel, ChannelMsg, Sig};

use crate::error::GitsshError;

// ── Public entry point ────────────────────────────────────────────────────────

/// Runs a full bidirectional relay between the local process stdio and the
/// given open SSH channel until the remote command exits.
///
/// # Returns
///
/// The remote exit code (0–255), or `128 + signal_number` if the remote
/// process was killed by a signal.
///
/// # Errors
///
/// Returns an error on SSH protocol failures or local I/O errors.
pub async fn relay_channel(channel: Channel<Msg>) -> Result<u32, GitsshError> {
    let (mut read_half, write_half) = channel.split();

    // Spawn the stdin → channel task.
    // The writer is `'static` (it owns its internal channel sender), so it can
    // be moved freely into a separate task without borrowing `write_half`.
    let mut channel_writer = write_half.make_writer();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        // Copy until stdin closes (git shuts its write end when done).
        tokio::io::copy(&mut stdin, &mut channel_writer).await?;
        // Signal EOF so the remote side knows no more data is coming.
        channel_writer.shutdown().await?;
        Ok::<_, std::io::Error>(())
    });

    // Main relay loop: channel → local stdout / stderr.
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit_code: Option<u32> = None;

    loop {
        let Some(msg) = read_half.wait().await else {
            // Channel closed by server.
            break;
        };

        match msg {
            ChannelMsg::Data { ref data } => {
                stdout.write_all(data).await?;
                // Flush immediately — Git reads output line-by-line.
                stdout.flush().await?;
            }
            ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                // ext == 1 → SSH_EXTENDED_DATA_STDERR
                stderr.write_all(data).await?;
                stderr.flush().await?;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                log::debug!("relay: remote process exited with code {exit_status}");
                exit_code = Some(exit_status);
                // Do not break here; further Data / Eof messages may follow.
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                ..
            } => {
                let sig_num = signal_number(&signal_name);
                // 128 + signal_number matches OpenSSH convention (FR-17).
                let code = 128_u32.saturating_add(sig_num);
                log::debug!(
                    "relay: remote process killed by signal {signal_name:?} \
                     (core_dumped={core_dumped}), exit code {code}"
                );
                exit_code = Some(code);
            }
            ChannelMsg::Close => break,
            // Eof, window adjustments, and any other messages are ignored:
            // keep looping to drain buffered data and await ExitStatus.
            _ => {}
        }
    }

    // Cancel the stdin task — if git already closed its pipe this is a no-op.
    stdin_task.abort();

    Ok(exit_code.unwrap_or(0))
}

// ── Signal → number mapping ───────────────────────────────────────────────────

/// Maps a russh [`Sig`] to its POSIX signal number.
///
/// Numbers follow POSIX 1003.1; `Custom` signals map to 0.
fn signal_number(sig: &Sig) -> u32 {
    // POSIX signal numbers used to compute OpenSSH-compatible exit codes.
    // A custom/unknown signal maps to 0 (no meaningful number available).
    match sig {
        Sig::HUP  => 1,
        Sig::INT  => 2,
        Sig::QUIT => 3,
        Sig::ILL  => 4,
        Sig::ABRT => 6,
        Sig::FPE  => 8,
        Sig::KILL => 9,
        Sig::SEGV => 11,
        Sig::PIPE => 13,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        Sig::USR1 => 10,
        Sig::Custom(_) => 0,
    }
}
