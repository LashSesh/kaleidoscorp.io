#![forbid(unsafe_code)]
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod windows {
    use ssk_desktop_client::{local_endpoint, DesktopClient, ReadError};
    use ssk_ui_contract::DesktopSnapshotV2;
    use tauri::{State, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    struct HostState(Result<DesktopClient, ReadError>);

    fn bundled_origin(url: &tauri::Url) -> bool {
        url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
                || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost")))
    }

    #[tauri::command]
    async fn get_panel_snapshot_v2<R: tauri::Runtime>(
        window: WebviewWindow<R>,
        state: State<'_, HostState>,
    ) -> Result<DesktopSnapshotV2, ReadError> {
        if window.label() != "main"
            || !bundled_origin(&window.url().map_err(|_| ReadError::Unavailable)?)
        {
            return Err(ReadError::Unavailable);
        }
        match &state.0 {
            Ok(client) => client.read_snapshot().await,
            Err(error) => Err(*error),
        }
    }

    pub fn run() {
        tauri::Builder::default()
            .manage(HostState(local_endpoint().map(DesktopClient::new)))
            .invoke_handler(tauri::generate_handler![get_panel_snapshot_v2])
            .setup(|app| {
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("ScorpioSync · Diagnose")
                    .inner_size(1024.0, 800.0)
                    .min_inner_size(600.0, 500.0)
                    .on_navigation(bundled_origin)
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                    .build()?;
                Ok(())
            })
            .run(tauri::generate_context!())
            .expect("desktop runtime failed");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn navigation_accepts_only_bundled_origins() {
            for url in [
                "tauri://localhost/index.html",
                "http://tauri.localhost/index.html",
            ] {
                assert!(bundled_origin(&url.parse().unwrap()));
            }
            for url in [
                "https://example.com",
                "http://localhost",
                "file:///C:/index.html",
                "http://tauri.localhost:5173",
                "http://user@tauri.localhost",
                "tauri://other/index.html",
            ] {
                assert!(!bundled_origin(&url.parse().unwrap()), "{url}");
            }
        }

        #[test]
        fn compiled_capabilities_restrict_commands_origins_and_windows() {
            let app = tauri::test::mock_builder()
                .manage(HostState(Err(ReadError::EndpointUnavailable)))
                .invoke_handler(tauri::generate_handler![get_panel_snapshot_v2])
                .build(tauri::generate_context!())
                .unwrap();
            let main =
                WebviewWindowBuilder::new(&app, "main", WebviewUrl::App("index.html".into()))
                    .build()
                    .unwrap();
            let other =
                WebviewWindowBuilder::new(&app, "other", WebviewUrl::App("index.html".into()))
                    .build()
                    .unwrap();
            let request = |command: &str, origin: &str| tauri::webview::InvokeRequest {
                cmd: command.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: origin.parse().unwrap(),
                body: tauri::ipc::InvokeBody::default(),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_string(),
            };
            tauri::test::assert_ipc_response(
                &main,
                request("get_panel_snapshot_v2", "http://tauri.localhost"),
                Err("endpoint_unavailable"),
            );
            for (window, command, origin) in [
                (&other, "get_panel_snapshot_v2", "http://tauri.localhost"),
                (&main, "get_panel_snapshot_v2", "https://example.com"),
                (&main, "plugin:window|close", "http://tauri.localhost"),
                (&main, "activate_profile", "http://tauri.localhost"),
            ] {
                let error = tauri::test::get_ipc_response(window, request(command, origin))
                    .expect_err("must deny");
                assert_ne!(
                    error, "endpoint_unavailable",
                    "denied before reaching handler"
                );
                assert!(
                    error.as_str().unwrap().contains("not allowed")
                        || error.as_str().unwrap().contains("not found"),
                    "{error}"
                );
            }
        }
    }
}

#[cfg(windows)]
fn main() {
    windows::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The desktop host currently requires Windows.");
}
