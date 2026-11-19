fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        let rc_x64 = r"O:\Windows Kits\10\bin\10.0.26100.0\x64";
        if std::path::Path::new(rc_x64).exists() {
            res.set_toolkit_path(rc_x64);
        }
        let _ = res.compile();
    }
}
