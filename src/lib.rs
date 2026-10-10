#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod auth;
mod config;
mod esplora;
mod guard;
mod idempotency;
mod locks;
mod mcp;
mod policy;
mod scan;
mod tx;
mod wallet;

#[cfg(target_arch = "wasm32")]
mod runtime;

#[cfg(target_arch = "wasm32")]
pub use runtime::SpendGuard;

#[cfg(target_arch = "wasm32")]
#[worker::event(fetch)]
pub async fn main(
    req: worker::Request,
    env: worker::Env,
    ctx: worker::Context,
) -> worker::Result<worker::Response> {
    runtime::main(req, env, ctx).await
}
