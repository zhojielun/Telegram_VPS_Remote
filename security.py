# -*- coding: utf-8 -*-
# security.py - 安全工具模块
import shlex
import os
import re
import subprocess
from pathlib import Path

# 危险字符正则
DANGEROUS_CHARS = re.compile(r'[;&|`$(){}!\n\r]')

def safe_shell_arg(arg: str) -> str:
    """安全转义 shell 参数，防止命令注入"""
    return shlex.quote(str(arg))

def safe_subprocess_run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    """安全执行子进程命令，强制使用列表形式"""
    kwargs.setdefault('shell', False)
    kwargs.setdefault('timeout', 30)
    kwargs.setdefault('capture_output', True)
    return subprocess.run(cmd, **kwargs)

def validate_port(port: str) -> bool:
    """验证端口号 (1-65535)"""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False

def validate_ip(ip: str) -> bool:
    """验证 IPv4 地址格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('/')[0].split('.')
    return all(0 <= int(p) <= 255 for p in parts)

def validate_cidr(cidr: str) -> bool:
    """验证 CIDR 格式"""
    if '/' not in cidr:
        return validate_ip(cidr)
    ip, mask = cidr.split('/', 1)
    return validate_ip(ip) and mask.isdigit() and 0 <= int(mask) <= 32

def validate_filename(filename: str) -> tuple[bool, str]:
    """
    验证文件名安全性，防止路径遍历
    返回: (是否安全, 错误信息或清理后的文件名)
    """
    if not filename:
        return False, "文件名不能为空"
    
    # 移除路径分隔符，只保留文件名
    safe_name = os.path.basename(filename)
    
    # 检查路径遍历
    if '..' in safe_name or '/' in safe_name or '\\' in safe_name:
        return False, "文件名包含非法字符"
    
    # 检查危险字符
    if DANGEROUS_CHARS.search(safe_name):
        return False, "文件名包含危险字符"
    
    # 检查长度
    if len(safe_name) > 255:
        return False, "文件名过长"
    
    # 检查空文件名
    if not safe_name or safe_name.startswith('.'):
        return False, "无效的文件名"
    
    return True, safe_name

def validate_path(path: str) -> tuple[bool, str]:
    """
    验证路径安全性
    返回: (是否安全, 错误信息或规范化路径)
    """
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
    SENSITIVE_DIRS = ['/etc/shadow', '/etc/passwd', '/root/.ssh', '/boot']
    for sensitive in SENSITIVE_DIRS:
        if real_path.startswith(sensitive):
            return False, f"禁止访问系统敏感目录"
    
    return True, real_path

def validate_docker_name(name: str) -> bool:
    """验证 Docker 容器名称"""
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_.-]+$'
    return bool(re.match(pattern, name)) and len(name) <= 128

def validate_port_mapping(mapping: str) -> tuple[bool, str]:
    """
    验证端口映射格式 (如 8080:80)
    返回: (是否有效, 错误信息或验证后的映射)
    """
    if ':' not in mapping:
        return False, "格式应为 主机端口:容器端口"
    
    parts = mapping.split(':')
    if len(parts) != 2:
        return False, "格式应为 主机端口:容器端口"
    
    host_port, container_port = parts
    
    if not validate_port(host_port):
        return False, f"主机端口无效: {host_port}"
    
    if not validate_port(container_port):
        return False, f"容器端口无效: {container_port}"
    
    return True, f"{host_port}:{container_port}"

def validate_volume_mapping(mapping: str) -> tuple[bool, str]:
    """
    验证卷挂载格式 (如 /host/path:/container/path)
    返回: (是否有效, 错误信息或验证后的映射)
    """
    if ':' not in mapping:
        return False, "格式应为 宿主路径:容器路径"
    
    parts = mapping.split(':')
    if len(parts) != 2:
        return False, "格式应为 宿主路径:容器路径"
    
    host_path, container_path = parts
    
    if not host_path or not container_path:
        return False, "路径不能为空"
    
    # 检查宿主路径是否使用绝对路径
    if not host_path.startswith('/'):
        return False, "宿主路径必须使用绝对路径"
    
    return True, f"{host_path}:{container_path}"

def validate_env_var(env: str) -> tuple[bool, str]:
    """
    验证环境变量格式 (如 KEY=VALUE)
    返回: (是否有效, 错误信息或验证后的变量)
    """
    if '=' not in env:
        return False, "格式应为 KEY=VALUE"
    
    key, value = env.split('=', 1)
    
    # 验证 KEY 格式
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key):
        return False, "变量名格式错误"
    
    if len(key) > 128:
        return False, "变量名过长"
    
    return True, f"{key}={value}"

def sanitize_html(text: str) -> str:
    """清理 HTML 特殊字符，防止 XSS"""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#x27;'))

def safe_file_operation(func):
    """文件操作装饰器，添加安全检查"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionError:
            return "❌ 权限不足"
        except FileNotFoundError:
            return "❌ 文件不存在"
        except Exception as e:
            return f"❌ 操作失败: {str(e)}"
    return wrapper
