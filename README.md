# FLASH

Desktop network status bar and connection observatory for sing-box (Windows).  
适用于 sing-box 的 Windows 桌面状态栏与连接观测组件。

---

## 1. Subscriptions / 订阅配置

Configuration file: `subscriptions.json` (see `subscriptions.example.json`).  
配置文件路径：`subscriptions.json`（参考模板 `subscriptions.example.json`）。

```json
{
  "active": "main",
  "subscriptions": {
    "main": "https://example.com/api/v1/client/subscribe?token=YOUR_TOKEN",
    "backup": "https://example.com/api/v1/client/subscribe?token=ANOTHER_TOKEN"
  }
}
```

Update & hot-reload / 同步更新与热重载：

```bash
python update_sub.py
```

---

## 2. Custom Rules / 自定义规则

Configuration file: `custom_rules.json` (see `custom_rules.example.json`).  
Rules here are persistent and will not be overwritten when updating subscriptions.  
配置文件路径：`custom_rules.json`（参考模板 `custom_rules.example.json`）。此文件规则持久生效，更新订阅时不会被覆盖。

```json
{
  "direct": {
    "domain_suffix": [
      "example.com",
      "local"
    ],
    "domain_keyword": [
      "internal"
    ],
    "ip_cidr": [
      "192.168.0.0/16",
      "10.0.0.0/8"
    ]
  },
  "proxy": {
    "domain_suffix": []
  }
}
```

---

## 3. Build & Run / 构建与运行

Prerequisites / 依赖环境：
- Windows 10 / 11 (x64)
- Rust toolchain (`cargo`)

Build / 编译：

```bash
cargo build --release
```

Binary output / 产物路径：`target/release/FLASH.exe`

Run / 启动：

```bash
cargo run --release
```

Controls / 操作方式：
- Top-left corner `(0, 0)`: Mouse left-click passes through to underlying windows.
- Right-click: Toggle horizontal action menu (start/stop, switch subscription, observatory, logs, exit).
- 屏幕左上角 `(0, 0)` 常驻：鼠标左键完全穿透。
- 鼠标右键：展开/收回水平操作栏（启动/停止、切换订阅、观测台、日志、退出）。
