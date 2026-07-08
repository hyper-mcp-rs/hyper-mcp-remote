use std::panic;
use std::sync::OnceLock;

use ctor::ctor;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

/// Number of daily log files to retain. On each roll, the appender prunes the
/// oldest files until at most this many remain, so logs don't grow unbounded.
///
/// `tracing_appender` may retain slightly fewer than this, so this is set one
/// above the intended week of history (see `Builder::max_log_files`).
const DEFAULT_MAX_LOG_FILES: usize = 8;

/// Environment variable overriding [`DEFAULT_MAX_LOG_FILES`].
const MAX_LOG_FILES_ENV: &str = "HYPER_MCP_REMOTE_LOG_MAX_FILES";

/// Resolve the log-retention count from an optional env value, falling back to
/// [`DEFAULT_MAX_LOG_FILES`] when it is unset or not a valid `usize`.
fn parse_max_log_files(value: Option<String>) -> usize {
    value
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_LOG_FILES)
}

#[cfg(not(test))]
static LOGGING: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

#[cfg(test)]
static LOGGING: OnceLock<()> = OnceLock::new();

/// Installs a custom panic hook that logs panics via `tracing::error!`
/// so they appear in the rolling log file instead of being silently
/// swallowed on stderr (which is unusable in a stdio MCP transport).
pub fn install_panic_hook() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };

        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        tracing::error!(
            panic.payload = %payload,
            panic.location = %location,
            "A panic occurred"
        );

        default_hook(info);
    }));
}

#[ctor(unsafe)]
fn _install_global_tracing() {
    LOGGING.get_or_init(|| {
        let fmt = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE);

        #[cfg(test)]
        {
            // Captured by the test harness (doesn't risk corrupting stdio MCP)
            fmt.with_test_writer().init();
        }

        #[cfg(not(test))]
        {
            // Cross-platform log directory
            let log_dir = std::env::var("HYPER_MCP_REMOTE_LOG_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::config_dir()
                        .map(|mut path| {
                            path.push("hyper-mcp-remote");
                            path.push("logs");
                            path
                        })
                        .expect("Unable to determine log directory")
                });

            std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");

            // Rolling daily log file that also prunes old files on each roll,
            // keeping only the most recent `max_log_files`.
            let max_log_files = parse_max_log_files(std::env::var(MAX_LOG_FILES_ENV).ok());
            let file_appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("hyper-mcp-remote.log")
                .max_log_files(max_log_files)
                .build(&log_dir)
                .expect("Failed to initialize rolling log file appender");

            // Non-blocking writer (important for stdio MCP)
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            fmt.with_writer(non_blocking).init();

            // Keep guard alive for flushing
            guard
        }
    });

    install_panic_hook();
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAX_LOG_FILES, MAX_LOG_FILES_ENV, parse_max_log_files};

    #[test]
    fn env_var_name_is_stable() {
        // Guards the documented configuration contract.
        assert_eq!(MAX_LOG_FILES_ENV, "HYPER_MCP_REMOTE_LOG_MAX_FILES");
    }

    #[test]
    fn unset_uses_default() {
        assert_eq!(parse_max_log_files(None), DEFAULT_MAX_LOG_FILES);
    }

    #[test]
    fn valid_value_is_parsed() {
        assert_eq!(parse_max_log_files(Some("3".to_string())), 3);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(parse_max_log_files(Some("  5\n".to_string())), 5);
    }

    #[test]
    fn zero_disables_pruning() {
        // `max_log_files(0)` tells the appender to retain everything.
        assert_eq!(parse_max_log_files(Some("0".to_string())), 0);
    }

    #[test]
    fn invalid_value_falls_back_to_default() {
        assert_eq!(
            parse_max_log_files(Some("not-a-number".to_string())),
            DEFAULT_MAX_LOG_FILES
        );
        assert_eq!(
            parse_max_log_files(Some("-1".to_string())),
            DEFAULT_MAX_LOG_FILES
        );
        assert_eq!(
            parse_max_log_files(Some(String::new())),
            DEFAULT_MAX_LOG_FILES
        );
    }
}
