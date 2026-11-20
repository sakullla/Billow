//! Minimal embedding example, mirroring how the iOS extension host (T3/T7)
//! drives the library without Tauri.
//!
//! Run with: `cargo run -p billow-kernel --example embed -- <config.yaml>`
//! The example starts the kernel, prints its identity, evaluates one target
//! against the rule set and stops it again.

fn main() -> Result<(), billow_kernel::StartError> {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: embed <config.yaml>");
        std::process::exit(2);
    };
    let (mut kernel, warnings) = billow_kernel::Kernel::start(
        std::path::Path::new(&path),
        None,
        billow_kernel::Limits::default(),
    )?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    println!("{}", kernel.identity().to_line());
    println!("features: {}", kernel.identity().features);
    let (action, label) = kernel.evaluate("example.com", None);
    println!("example.com -> {} ({})", action.as_str(), label);
    println!("stats: {:?}", kernel.stats());
    kernel.stop().expect("clean stop");
    Ok(())
}
