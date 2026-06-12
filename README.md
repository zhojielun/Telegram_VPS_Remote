# 🚀 Telegram VPS Remote Controller

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-latest-blue.svg)](https://www.docker.com/)

通过 Telegram Bot 轻松管理你的 VPS 服务器 - 系统监控、Docker 管理、安全防护一应俱全!

## ✨ 核心功能

- 📊 **系统监控**: CPU/内存/磁盘/流量实时监控
- 🐳 **Docker 管理**: 容器启停、日志查看、健康检查
- 🛡️ **安全防护**: SSH 爆破防御、IP 黑名单、审计日志
- 📈 **流量管理**: 月流量统计、预警、排行榜
- 🌐 **网络工具**: 端口扫描、内网控制、连接监控
- ☁️ **备份管理**: 定时备份、一键恢复
- 🔄 **IP 监控**: IP 变化检测、API 执行

## 🚀 快速开始 (Docker)

### 1. 创建配置文件

```bash
mkdir -p /opt/vps_bot
cat > /opt/vps_bot/config.json << 'EOF'
{
  "bot_token": "你的Bot Token",
  "admin_id": 你的Telegram ID,
  "server_remark": "我的VPS"
}
EOF
```

### 2. 一键启动

```bash
docker run -d \
  --name vps-bot \
  --restart always \
  -v /opt/vps_bot/config.json:/app/config.json \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --privileged \
  ghcr.io/zhojielun/telegram_vps_remote:latest
```

### 3. 或使用 Docker Compose

```bash
git clone https://github.com/zhojielun/Telegram_VPS_Remote.git
cd Telegram_VPS_Remote
# 编辑 config.json
docker-compose up -d
```

## 📋 项目结构

```
Telegram_VPS_Remote/
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/docker-publish.yml
├── main.py              # 主程序
├── config.py            # 配置管理
├── security.py          # 安全模块
├── utils.py             # 工具函数
├── requirements.txt     # Python 依赖
└── modules/
    ├── system.py        # 系统监控
    ├── docker_mgr.py    # Docker 管理
    ├── network.py       # 网络工具
    ├── backup.py        # 备份管理
    ├── sentinel.py      # 安全哨兵
    ├── settings.py      # 设置管理
    ├── health_check.py  # 健康检查
    └── ip_monitor.py    # IP 监控
```

## 🔧 配置

```json
{
  "bot_token": "123456:ABC-DEF...",
  "admin_id": 123456789,
  "server_remark": "我的VPS",
  "ban_threshold": 5,
  "traffic_limit_gb": 1024
}
```

## 📱 使用

在 Telegram 中发送 `/start` 打开主菜单。

## 📝 许可证

[MIT License](LICENSE)

---

**⭐ 如果这个项目对你有帮助，请给个 Star!**
