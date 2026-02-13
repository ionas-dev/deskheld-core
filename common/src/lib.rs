pub mod certificate;
pub mod config;
pub mod connection;

use std::{
    future::Future,
    sync::{Once, OnceLock},
};

static INSTALL_RUSTLS_PROVIDER: Once = Once::new();
static INIT_RUST_LOGGER: Once = Once::new();
static TOKIO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

pub fn ensure_rustls_ring_provider() {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn init_rust_logging_from_env_once() {
    INIT_RUST_LOGGER.call_once(|| {
        if std::env::var_os("RUST_LOG").is_none() {
            return;
        }
        let mut builder = env_logger::Builder::from_env(env_logger::Env::default());
        builder.format_timestamp_millis();
        let _ = builder.try_init();
    });
}

fn runtime() -> &'static tokio::runtime::Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to initialize global tokio runtime")
    })
}

pub fn with_tokio_runtime_context<T>(f: impl FnOnce() -> T) -> T {
    let _guard = runtime().enter();
    f()
}

pub fn spawn_task<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    runtime().spawn(future)
}

uniffi::setup_scaffolding!("Deskheld");
