use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.join("../..");
    let wasm_crate = workspace.join("crates/rdap-wasm");
    let out_js = manifest_dir.join("static/wasm/rdap_wasm.js");
    let out_wasm = manifest_dir.join("static/wasm/rdap_wasm_bg.wasm");

    let mut sources: Vec<PathBuf> =
        vec![wasm_crate.join("Cargo.toml"), workspace.join("Cargo.lock")];
    walk(&wasm_crate.join("src"), &mut sources);

    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }
    // Watching the artifacts too, so deleting them forces a rebuild.
    println!("cargo:rerun-if-changed={}", out_js.display());
    println!("cargo:rerun-if-changed={}", out_wasm.display());

    if !needs_build(&sources, &[&out_js, &out_wasm]) {
        return;
    }

    println!("cargo:warning=building rdap-wasm for the browser (wasm32-unknown-unknown)");

    let status = Command::new("wasm-pack")
        .arg("build")
        .arg(&wasm_crate)
        .args(["--target", "web", "--release"])
        .current_dir(manifest_dir)
        .env("CARGO_TARGET_DIR", workspace.join("target/wasm-build"))
        .status()
        .expect(
            "failed to run wasm-pack; install it with `cargo install wasm-pack` \
             and the target with `rustup target add wasm32-unknown-unknown`",
        );
    assert!(status.success(), "wasm-pack build of rdap-wasm failed");

    let pkg = wasm_crate.join("pkg");
    std::fs::create_dir_all(out_js.parent().unwrap()).expect("create static/wasm dir");
    std::fs::copy(pkg.join("rdap_wasm.js"), &out_js).expect("copy rdap_wasm.js");
    std::fs::copy(pkg.join("rdap_wasm_bg.wasm"), &out_wasm).expect("copy rdap_wasm_bg.wasm");
    let _ = std::fs::remove_dir_all(&pkg);
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}

fn needs_build(sources: &[PathBuf], artifacts: &[&Path]) -> bool {
    let artifact_times: Vec<_> = artifacts
        .iter()
        .filter_map(|path| path.metadata().and_then(|m| m.modified()).ok())
        .collect();
    if artifact_times.len() != artifacts.len() {
        return true;
    }
    let newest_artifact = artifact_times.into_iter().min().unwrap();
    sources
        .iter()
        .filter_map(|path| path.metadata().and_then(|m| m.modified()).ok())
        .any(|source_time| source_time > newest_artifact)
}
