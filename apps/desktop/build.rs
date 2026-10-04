fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=../../ui/desktop/dist");
        tauri_build::try_build(
            tauri_build::Attributes::new()
                .app_manifest(tauri_build::AppManifest::new().commands(&["get_panel_snapshot_v2"])),
        )
        .expect("desktop host build configuration");
    }
}
