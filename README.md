# FLASH

Windows desktop network HUD & connection observatory for [sing-box](https://github.com/SagerNet/sing-box).  
适用于 sing-box 的 Windows 桌面轻量网络状态栏与连接观测台。

---

## Quick Start / 快速上手

`FLASH.exe` communicates with `sing-box` through its Clash REST API (`127.0.0.1:9090`).  
`FLASH.exe` 通过 Clash REST API 接口（`127.0.0.1:9090`）与 `sing-box` 通信。

### 1. Configure sing-box / 配置 sing-box
Add the experimental Clash API controller to your `config.json`:  
在你的 `config.json` 中添加 Clash API 控制器配置：

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090"
    }
  }
}
```

### 2. Run / 运行
1. Start `sing-box` (CLI, GUI, or Windows Service).  
   启动 `sing-box`（命令行、图形端或 Windows 服务模式）。
2. Run `FLASH.exe` (Run as Administrator recommended for full route cleanup on exit).  
   运行 `FLASH.exe`（建议以管理员身份运行以支持退出时清理路由）。

---

## Controls / 操作说明

- **Desktop HUD / 屏幕左上角 `(0, 0)` 常驻栏**:
  - Displays real-time upload/download speed, sing-box memory, and active connections.
  - Left-click passes through (`HTTRANSPARENT`) to underlying applications.
  - Right-click toggles the horizontal action menu.
  - 实时显示上下行网速、内存占用、活跃连接数。
  - 鼠标左键完全穿透，不遮挡底层窗口点击。
  - 鼠标右键展开/收回水平胶囊菜单。

- **Realtime Observatory / 实时连接观测台**:
  - Click `📊 观测台` in the menu.
  - 9 columns: Duration, Protocol, Source, Destination Host/IP, Chain & Rule, Live Speed, Total I/O, State.
  - Click headers to sort (`▲`/`▼`). Type anywhere to filter. Press `Esc` to clear search.
  - 菜单点击 `📊 观测台` 唤出独立窗口。
  - 9 列会话追踪：连接时长、协议入站、来源、目标域名/IP、分流链条与规则、实时速率、累计流量、状态。
  - 表头点击正反排序，实时键盘输入检索过滤，`Esc` 一键清空。

- **Clean Teardown / 纯净退出**:
  - Click `✕ 退出` in the menu. Stops sing-box, kills orphaned processes, purges routes, and flushes DNS.
  - 菜单点击 `✕ 退出`：终止 sing-box 进程，自动回收虚拟网卡路由并刷新 DNS。

---

## Directory Structure (Optional) / 推荐目录结构（可选）

If you want `FLASH.exe` to manage start/stop and subscription switching, place files alongside `sing-box`:  
如需通过菜单启动内核或切换多订阅，推荐将 `FLASH.exe` 与 `sing-box` 置于同一目录：

```text
├── FLASH.exe
├── sing-box.exe
├── config.json
├── subscriptions.json          # Optional / 可选
└── update_sub.py               # Optional / 可选
```

### Subscriptions / 订阅配置 (`subscriptions.json`)

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

### Custom Rules / 自定义规则 (`custom_rules.json`)

Rules here are persistent and will not be overwritten when updating subscriptions:  
此文件规则持久生效，更新订阅时不会被覆盖：

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

## Build / 本地构建

Prerequisites: Windows 10/11 x64, Rust toolchain.

```bash
cargo build --release
```

Output: `target/release/FLASH.exe`
