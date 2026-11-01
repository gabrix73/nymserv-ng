use std::io::Write;
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MtaError {
    #[error("failed to spawn sendmail process: {0}")]
    SpawnError(String),
    #[error("sendmail returned non-zero exit code: {0}")]
    ProcessFailed(i32),
    #[error("pipe IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Dispatches an RFC 5322 formatted email to the local MTA (e.g. Postfix / sendmail)
pub fn send_email(mta_cmd: &str, raw_email: &[u8]) -> Result<(), MtaError> {
    let parts: Vec<&str> = mta_cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err(MtaError::SpawnError("empty mta command".to_string()));
    }

    let mut child = Command::new(parts[0])
        .args(&parts[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| MtaError::SpawnError(e.to_string()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(raw_email)?;
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(MtaError::ProcessFailed(status.code().unwrap_or(-1)));
    }
    Ok(())
}
