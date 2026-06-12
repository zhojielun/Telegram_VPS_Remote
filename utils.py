# -*- coding: utf-8 -*-
# utils.py - 工具函数模块 (安全加固版)
import subprocess, requests, os, glob, zlib, re
from datetime import datetime
from config import AUDIT_FILE, TOKEN, ALLOWED_USER_ID

# 导入安全模块
from security import safe_subprocess_run, validate_ip, sanitize_html

def get_public_ip():
    """获取公网IP地址"""
    try:
        result = safe_subprocess_run(
            ["curl", "-s", "--max-time", "2", "http://checkip.amazonaws.com"],
            timeout=5
        )
        ip = result.stdout.decode('utf-8', errors='ignore').strip()
        if ip and "curl" not in ip.lower() and len(ip) < 50 and validate_ip(ip):
            return ip
    except:
        pass
    
    # 降级方案
    try:
        result = safe_subprocess_run(
            ["curl", "-s", "--max-time", "2", "http://ifconfig.me"],
            timeout=5
        )
        ip = result.stdout.decode('utf-8', errors='ignore').strip()
        if ip and len(ip) < 50 and validate_ip(ip):
            return ip
    except:
        pass
    
    return "未知IP"

def get_ip_info(ip):
    """获取IP地理信息"""
    # 过滤内网IP和无效IP
    if not validate_ip(ip):
        return "📍 无效IP"
    
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return "🏠 内网"
    
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,city", 
            timeout=2
        ).json()
        
        if r.get('status') == 'success':
            country = r.get('country', '')
            city = r.get('city', '')
            return f"📍 {sanitize_html(country)} {sanitize_html(city)}"
        else:
            return "📍 未知"
    except:
        return "📍 查询失败"

def get_audit_tail(n=10):
    """读取审计日志的最后 N 行 - 安全加固版"""
    if not os.path.exists(AUDIT_FILE):
        return "📭 暂无日志记录"
    
    try:
        # 验证行数参数
        try:
            n = max(1, min(100, int(n)))
        except (ValueError, TypeError):
            n = 10
        
        # 使用列表形式执行命令
        result = safe_subprocess_run(
            ["tail", "-n", str(n), AUDIT_FILE],
            timeout=5
        )
        
        output = result.stdout.decode('utf-8', errors='ignore')
        if output.strip():
            return sanitize_html(output)
        else:
            return "📭 日志文件为空"
    except Exception as e:
        return f"❌ 读取失败: {sanitize_html(str(e))}"

def log_audit(actor, action, target):
    """记录操作审计日志 - 安全加固版"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # 确保日志目录存在
        audit_dir = os.path.dirname(AUDIT_FILE)
        if audit_dir and not os.path.exists(audit_dir):
            os.makedirs(audit_dir, mode=0o750, exist_ok=True)
        
        with open(AUDIT_FILE, 'a', encoding='utf-8') as f:
            # 清理日志内容，防止日志注入
            safe_action = sanitize_html(str(action))
            safe_target = sanitize_html(str(target))
            f.write(f"[{timestamp}] [{actor}] {safe_action}: {safe_target}\n")
    except Exception as e:
        print(f"⚠️ 日志记录失败: {e}")

def get_path_id(path):
    """为路径生成唯一ID (用于备份标识)"""
    # 清理路径，防止路径注入
    clean_path = os.path.normpath(path)
    return str(zlib.crc32(clean_path.encode('utf-8')))

async def split_and_send(file_path, caption):
    """发送文件到 Telegram - 安全加固版"""
    if not TOKEN:
        return "❌ Bot Token 未配置"
    
    url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
    
    # 验证文件路径
    if not os.path.exists(file_path):
        return "❌ 文件不存在"
    
    if not os.path.isfile(file_path):
        return "❌ 路径不是文件"
    
    # 检查文件大小
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        return "❌ 无法读取文件大小"
    
    # Telegram 文件大小限制: 50MB
    if file_size > 49 * 1024 * 1024:
        return f"❌ 文件过大 ({file_size / 1024**2:.1f} MB), 请手动处理"
    
    if file_size == 0:
        return "❌ 文件为空"
    
    try:
        with open(file_path, 'rb') as f:
            response = requests.post(
                url, 
                data={'chat_id': ALLOWED_USER_ID, 'caption': str(caption)[:1024]}, 
                files={'document': f}, 
                timeout=120
            )
            
            if response.status_code == 200:
                return "✅ 发送成功"
            else:
                return f"❌ 发送失败: {sanitize_html(response.text[:100])}"
    except Exception as e:
        return f"❌ 发送失败: {sanitize_html(str(e))}"

def format_bytes(bytes_value):
    """格式化字节数为人类可读格式"""
    try:
        bytes_value = float(bytes_value)
        if bytes_value < 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    except (ValueError, TypeError):
        return "0 B"

def safe_run_command(cmd, timeout=30):
    """安全执行系统命令 - 安全加固版"""
    try:
        if isinstance(cmd, str):
            # 对于字符串命令，使用列表形式
            import shlex
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = cmd
        
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            timeout=timeout,
            text=True,
            shell=False  # 安全: 禁用 shell
        )
        
        if result.returncode == 0:
            return sanitize_html(result.stdout.strip())
        else:
            return sanitize_html(result.stderr.strip()) if result.stderr else "命令执行失败"
    except subprocess.TimeoutExpired:
        return f"❌ 命令超时 (>{timeout}秒)"
    except FileNotFoundError:
        return "❌ 命令不存在"
    except Exception as e:
        return f"❌ 执行失败: {sanitize_html(str(e))}"

def validate_file_path(path):
    """验证文件路径安全性"""
    if not path:
        return False, "路径不能为空"
    
    # 必须是绝对路径
    if not os.path.isabs(path):
        return False, "必须使用绝对路径"
    
    # 规范化路径
    try:
        real_path = os.path.realpath(path)
    except Exception:
        return False, "无效路径"
    
    # 禁止访问敏感目录
    SENSITIVE_DIRS = ['/etc/shadow', '/etc/passwd', '/boot']
    for sensitive in SENSITIVE_DIRS:
        if real_path.startswith(sensitive):
            return False, "禁止访问系统敏感目录"
    
    return True, real_path
