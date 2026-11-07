//! Shared plumbing for the `support-bin` CLI binaries.
//!
//! Each binary in `src/bin/` stays thin by leaning on these helpers instead of
//! re-implementing them: a blocking HTTP client builder, a one-shot text fetcher
//! that maps non-success statuses to errors, and an exit-code wrapper that prints
//! `<name>: <error>` on failure. The library already depends on
//! `reqwest`'s `blocking` feature, so nothing new is pulled in here.

use std::error::Error;
use std::process::ExitCode;
use std::time::Duration;

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
}
