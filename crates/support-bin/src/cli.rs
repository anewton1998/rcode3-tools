//! Shared plumbing for the `support-bin` CLI binaries.
//!
//! Each binary in `src/bin/` stays thin by leaning on these helpers instead of
//! re-implementing them: a blocking HTTP client builder, a one-shot text fetcher
//! that maps non-success statuses to errors, and an exit-code wrapper that prints
//! `<name>: <error>` on failure. The library already depends on
//! `reqwest`'s `blocking` feature, so nothing new is pulled in here.

use std::error::Error;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

/// Upper bound on the bytes [`read_first_line`] will pull from a file, so a
/// newline-less or huge payload can't drive an unbounded allocation. 4 KiB is
/// far beyond any real first record in the payloads these binaries inspect.
const FIRST_LINE_READ_LIMIT: u64 = 4096;

/// Build a blocking HTTP client with the given request timeout.
pub fn http_client(timeout: Duration) -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
}

/// GET a URL and return its body, mapping a non-success status to an error.
pub fn fetch_text(client: &reqwest::blocking::Client, url: &str) -> Result<String, Box<dyn Error>> {
    let response = client.get(url).send()?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {url} failed: HTTP {status}").into());
    }
    response.text().map_err(Into::into)
}

/// GET a URL and stream its body to `path`, creating parent directories as
/// needed, and return the number of bytes written.
///
/// Used for large payloads (the NRO extended stats file is ~57 MB of
/// `application/octet-stream`) where buffering the whole body as a `String`
/// via [`fetch_text`] would be wasteful. The response body is copied straight
/// to disk, so peak memory stays flat regardless of file size.
pub fn download_to_file(
    client: &reqwest::blocking::Client,
    url: &str,
    path: &Path,
) -> Result<u64, Box<dyn Error>> {
    let response = client.get(url).send()?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {url} failed: HTTP {status}").into());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    let mut reader = response;
    let written = std::io::copy(&mut reader, &mut file)?;
    Ok(written)
}

/// Read the first line of `path` with any trailing CR/LF trimmed.
///
/// The read is capped at [`FIRST_LINE_READ_LIMIT`] bytes and decoded lossily, so
/// a pathological payload with no newline (or invalid UTF-8) can never make
/// this allocate the whole file or fail — the caller's guard simply sees a
/// non-matching first line. Returns an empty string for an empty file, letting
/// callers distinguish "nothing there" from "a first line that is present but
/// wrong".
pub fn read_first_line(path: &Path) -> Result<String, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file).take(FIRST_LINE_READ_LIMIT);
    let mut buf = Vec::new();
    reader.read_until(b'\n', &mut buf)?;
    let line = String::from_utf8_lossy(&buf);
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Run a fallible closure, returning [`ExitCode::SUCCESS`] on `Ok` and printing
/// `<name>: <error>` to stderr and returning [`ExitCode::FAILURE`] on `Err`.
///
/// Lets each binary's `main` stay a one-liner while still attributing failures to
/// the binary that produced them.
pub fn run_or_exit(name: &str, f: impl FnOnce() -> Result<(), Box<dyn Error>>) -> ExitCode {
    match f() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{name}: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn run_or_exit_returns_success_on_ok() {
        // GIVEN a closure that succeeds
        // WHEN wrapped
        let code = run_or_exit("test-bin", || Ok(()));
        // THEN the exit code is success
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_or_exit_returns_failure_on_err() {
        // GIVEN a closure that fails with a boxed error
        // WHEN wrapped
        let code = run_or_exit("test-bin", || Err("boom".into()));
        // THEN the exit code is failure
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[test]
    fn http_client_builds_with_timeout() {
        // GIVEN a timeout
        // WHEN a client is built
        let client = http_client(Duration::from_secs(5));
        // THEN it builds without error
        assert!(client.is_ok());
    }

    /// Write `content` to a uniquely-named temp file and return its path.
    fn temp_file(content: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "support-bin-cli-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("payload");
        std::fs::write(&path, content).expect("write temp file");
        path
    }

    #[test]
    fn read_first_line_trims_crlf() {
        // GIVEN a file whose first line ends with CRLF
        let path = temp_file(b"first\r\nsecond\r\n");
        // WHEN the first line is read
        let line = read_first_line(&path).expect("read");
        // THEN the trailing CR/LF is trimmed and only the first line returns
        assert_eq!(line, "first");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn read_first_line_handles_no_trailing_newline() {
        // GIVEN a single line with no trailing newline
        let path = temp_file(b"only-line");
        // WHEN read
        let line = read_first_line(&path).expect("read");
        // THEN the whole line is returned
        assert_eq!(line, "only-line");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn read_first_line_returns_empty_for_empty_file() {
        // GIVEN an empty file
        let path = temp_file(b"");
        // WHEN read
        let line = read_first_line(&path).expect("read");
        // THEN an empty string is returned (distinguishing "nothing there")
        assert_eq!(line, "");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn read_first_line_caps_a_newlineless_huge_payload() {
        // GIVEN a payload with no newline, larger than the read cap
        let path = temp_file(&vec![b'x'; 100_000]);
        // WHEN the first line is read
        let line = read_first_line(&path).expect("read");
        // THEN it is bounded to the cap rather than the whole file
        assert_eq!(line.len(), 4096);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
