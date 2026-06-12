# -*- coding: utf-8 -*-
# config.py - 配置管理模块 (安全加固版)
import json
import os
import re
import tempfile

# 配置文件路径 - 支持环境变量覆盖
CONFIG_FILE = os.environ.get("VPSBOT_CONFIG", "/root/sentinel_config.json")
SSH_FILE = os.environ.get("VPSBOT_SSH", "/root/.ssh/authorized_keys")
AUDIT_FILE = os.environ.get("VPSBOT_AUDIT", "/root/vps_bot-x/bot.log")

# 默认配置模板
DEFAULT_CONFIG = {
    "bot_token": "",
    "admin_id": 0,
    "server_remark": "VPS_bot-X",
    "traffic_limit_gb": 1024,
    "backup_paths": [],
    "daily_report_times": ["08:00", "20:00"],
    "command_prefix": "kk",
    "ban_threshold": 5,
    "ban_duration": "permanent",
    "ports": {},
    "backup_exclude": ["*.log", "*.tmp", "__pycache__", "cache"],
    "auto_backup": {"mode": "off", "time": "03:00"},
    # IP 监控配置
    "ip_monitor": {
        "enabled": False,
        "check_interval_minutes": 5,
        "last_known_ip": ""
    },
    # API 共享参数
    "api_service_id": "",
    "api_token": "",
    # API 模板列表
    "api_templates": []
}

def validate_token(token):
    """验证 Bot Token 格式"""
    if not token:
        return False
    return bool(re.match(r'^\d+:[A-Za-z0-9_-]+$', token))

def validate_admin_id(admin_id):
    """验证管理员ID"""
    try:
        aid = int(admin_id)
        return aid > 0
    except (ValueError, TypeError):
        return False

def validate_config(config):
    """验证配置有效性"""
    errors = []
    
    # 验证 bot_token
    if config.get('bot_token') and not validate_token(config['bot_token']):
        errors.append("bot_token 格式无效")
    
    # 验证 admin_id
    if config.get('admin_id') and not validate_admin_id(config['admin_id']):
        errors.append("admin_id 格式无效")
    
    # 验证 traffic_limit_gb
    try:
        limit = float(config.get('traffic_limit_gb', 1024))
        if limit <= 0:
            errors.append("traffic_limit_gb 必须大于 0")
    except (ValueError, TypeError):
        errors.append("traffic_limit_gb 格式无效")
    
    # 验证 command_prefix
    prefix = config.get('command_prefix', 'kk')
    if not re.match(r'^[a-z0-9_]{3,20}$', prefix):
        errors.append("command_prefix 格式无效 (需要3-20位小写字母/数字/下划线)")
    
    return errors

def load_config():
    """加载配置文件 - 安全加固版"""
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # 合并默认配置
        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        
        return merged
    except json.JSONDecodeError:
        print(f"Warning: Invalid JSON in {CONFIG_FILE}, using defaults")
        return DEFAULT_CONFIG.copy()
    except Exception as e:
        print(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

def save_config(config):
    """保存配置文件 - 安全加固版 (原子写入)"""
    try:
        # 确保配置目录存在
        config_dir = os.path.dirname(CONFIG_FILE)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, mode=0o750, exist_ok=True)
        
        # 使用临时文件进行原子写入
        fd, tmp_path = tempfile.mkstemp(
            dir=config_dir or '/tmp',
            suffix='.json.tmp',
            prefix='vpsbot_'
        )
        
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            # 原子替换
            os.replace(tmp_path, CONFIG_FILE)
            
            # 设置安全权限
            os.chmod(CONFIG_FILE, 0o640)
        except Exception:
            # 清理临时文件
            try:
                os.unlink(tmp_path)
            except:
                pass
            raise
            
    except Exception as e:
        print(f"Error saving config: {e}")
        return False
    
    return True

# 加载配置供 main.py 使用
_conf = load_config()

# 映射 main.py 需要的变量名
TOKEN = _conf.get("bot_token", "")
ALLOWED_USER_ID = _conf.get("admin_id", 0)
ALLOWED_USER_IDS = [ALLOWED_USER_ID] if ALLOWED_USER_ID else []

# 配置加载函数
def load_ports():
    """从配置中加载端口信息"""
    config = load_config()
    return config.get('ports', {})

def save_ports(data):
    """保存端口信息到配置"""
    config = load_config()
    config['ports'] = data
    save_config(config)
