# -*- coding: utf-8 -*-
# modules/ip_monitor.py - IP 监控与 API 执行模块 (灵活配置版)
import requests
import re
from datetime import datetime
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from config import load_config, save_config
from utils import log_audit, get_public_ip
from security import sanitize_html, validate_ip

# ==================== IP 监控功能 ====================

def get_current_ip():
    """获取当前公网 IP"""
    return get_public_ip()

def get_last_known_ip():
    """获取上次记录的 IP"""
    conf = load_config()
    return conf.get('ip_monitor', {}).get('last_known_ip', '')

def update_last_known_ip(ip):
    """更新上次记录的 IP"""
    conf = load_config()
    if 'ip_monitor' not in conf:
        conf['ip_monitor'] = {}
    conf['ip_monitor']['last_known_ip'] = ip
    save_config(conf)

def check_ip_changed():
    """检查 IP 是否发生变化"""
    current_ip = get_current_ip()
    last_ip = get_last_known_ip()
    
    if not current_ip or current_ip == "未知IP":
        return False, last_ip, current_ip
    
    if last_ip == "":
        update_last_known_ip(current_ip)
        return False, "", current_ip
    
    if current_ip != last_ip:
        update_last_known_ip(current_ip)
        return True, last_ip, current_ip
    
    return False, last_ip, current_ip

# ==================== 灵活 API 功能 ====================

def get_api_templates():
    """获取所有 API 模板"""
    conf = load_config()
    return conf.get('api_templates', [])

def save_api_templates(templates):
    """保存 API 模板"""
    conf = load_config()
    conf['api_templates'] = templates
    save_config(conf)

def add_api_template(name, url, method="GET", headers=None, body=None):
    """添加 API 模板"""
    templates = get_api_templates()
    
    # 生成唯一 ID
    template_id = f"tpl_{len(templates) + 1}_{int(datetime.now().timestamp())}"
    
    template = {
        'id': template_id,
        'name': name,
        'url': url,
        'method': method.upper(),
        'headers': headers or {},
        'body': body,
        'enabled': True
    }
    
    templates.append(template)
    save_api_templates(templates)
    return template_id

def remove_api_template(template_id):
    """删除 API 模板"""
    templates = get_api_templates()
    templates = [t for t in templates if t.get('id') != template_id]
    save_api_templates(templates)

def toggle_api_template(template_id):
    """启用/禁用 API 模板"""
    templates = get_api_templates()
    for t in templates:
        if t.get('id') == template_id:
            t['enabled'] = not t.get('enabled', True)
            break
    save_api_templates(templates)

def get_api_template_by_id(template_id):
    """根据 ID 获取模板"""
    templates = get_api_templates()
    for t in templates:
        if t.get('id') == template_id:
            return t
    return None

def validate_api_url(url):
    """验证 API URL 安全性"""
    if not url:
        return False, "URL 不能为空"
    
    # 检查是否包含危险字符
    if re.search(r'[;&|`$()]', url):
        return False, "URL 包含非法字符"
    
    # 必须是 http:// 或 https://
    if not (url.startswith('http://') or url.startswith('https://')):
        return False, "URL 必须以 http:// 或 https:// 开头"
    
    # 检查 URL 格式
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        if not parsed.netloc:
            return False, "无效的 URL 格式"
        
        # 内网 IP 检查 (允许)
        # 这里不禁止内网 IP，因为很多服务商的 API 在内网
        
        return True, "URL 有效"
    except Exception as e:
        return False, f"URL 验证失败: {str(e)}"

def build_url_from_template(template, variables=None):
    """
    从模板构建 URL
    支持变量替换: {service_id}, {token}, {current_ip} 等
    """
    url = template.get('url', '')
    if variables:
        for key, value in variables.items():
            url = url.replace(f'{{{key}}}', str(value))
    return url

def call_api_template(template_id, variables=None):
    """
    调用 API 模板
    返回: (成功, 响应数据或错误信息)
    """
    template = get_api_template_by_id(template_id)
    if not template:
        return False, "模板不存在"
    
    if not template.get('enabled', True):
        return False, "模板已禁用"
    
    try:
        url = build_url_from_template(template, variables)
        method = template.get('method', 'GET').upper()
        headers = template.get('headers', {})
        body = template.get('body')
        
        # 如果 body 也是模板，替换变量
        if body and variables:
            for key, value in variables.items():
                body = body.replace(f'{{{key}}}', str(value))
        
        # 安全选项
        kwargs = {
            'timeout': 30,
            'allow_redirects': False,
            'headers': headers
        }
        
        # HTTPS 才验证证书，HTTP 不验证 (内网环境)
        if url.startswith('https://'):
            kwargs['verify'] = True
        else:
            kwargs['verify'] = False  # HTTP 或内网
        
        # 发送请求
        if method == 'POST':
            kwargs['data'] = body
            response = requests.post(url, **kwargs)
        else:
            response = requests.get(url, **kwargs)
        
        # 解析响应
        if response.status_code == 200:
            try:
                data = response.json()
                return True, data
            except:
                return True, {'raw': response.text[:1000]}
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
            
    except requests.exceptions.Timeout:
        return False, "请求超时"
    except requests.exceptions.SSLError:
        return False, "SSL 证书错误"
    except requests.exceptions.ConnectionError:
        return False, "连接失败"
    except Exception as e:
        return False, f"请求失败: {str(e)}"

def get_shared_variables():
    """获取共享变量 (service_id, token 等)"""
    conf = load_config()
    return {
        'service_id': conf.get('api_service_id', ''),
        'token': conf.get('api_token', ''),
        'current_ip': get_current_ip()
    }

def call_change_ip_api(template_id):
    """调用更换 IP API"""
    variables = get_shared_variables()
    success, data = call_api_template(template_id, variables)
    
    if success:
        log_audit("USER", "API更换IP", f"成功: {str(data)[:100]}")
    else:
        log_audit("USER", "API更换IP", f"失败: {data}")
    
    return success, data

def call_status_api(template_id):
    """调用查询状态 API"""
    variables = get_shared_variables()
    success, data = call_api_template(template_id, variables)
    
    if success:
        log_audit("USER", "API查询状态", f"成功: {str(data)[:100]}")
    else:
        log_audit("USER", "API查询状态", f"失败: {data}")
    
    return success, data

# ==================== UI 菜单 ====================

def get_ip_monitor_menu():
    """构建 IP 监控菜单"""
    conf = load_config()
    ip_monitor = conf.get('ip_monitor', {})
    
    current_ip = get_current_ip()
    last_ip = get_last_known_ip()
    is_enabled = ip_monitor.get('enabled', False)
    interval = ip_monitor.get('check_interval_minutes', 5)
    
    templates = get_api_templates()
    enabled_count = len([t for t in templates if t.get('enabled', True)])
    
    txt = (
        f"🌐 <b>IP 监控中心</b>\n"
        f"━━━━━━━━━━━━━━━\n\n"
        f"📡 <b>当前公网 IP</b>: <code>{current_ip}</code>\n"
        f"📝 <b>上次记录 IP</b>: <code>{last_ip or '无'}</code>\n"
        f"🔄 <b>监控状态</b>: {'✅ 已启用' if is_enabled else '❌ 未启用'}\n"
        f"⏱️ <b>检测间隔</b>: {interval} 分钟\n\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🔌 <b>API 模板</b>: {enabled_count}/{len(templates)} 个已启用\n"
    )
    
    kb = [
        [InlineKeyboardButton(
            f"{'✅ 禁用' if is_enabled else '▶️ 启用'} 监控",
            callback_data="ip_mon_toggle"
        )],
        [InlineKeyboardButton("🔄 立即检测", callback_data="ip_mon_check"),
         InlineKeyboardButton("📝 手动设置IP", callback_data="ip_mon_set")],
        [InlineKeyboardButton("━━━━━━━━━━━━━━━", callback_data="none")],
        [InlineKeyboardButton("📋 API 模板管理", callback_data="ip_api_list")],
        [InlineKeyboardButton("⚙️ 共享参数设置", callback_data="ip_api_shared")],
    ]
    
    kb.append([InlineKeyboardButton("🔙 返回主菜单", callback_data="back")])
    
    return txt, InlineKeyboardMarkup(kb)

def get_api_list_menu():
    """构建 API 模板列表菜单"""
    templates = get_api_templates()
    
    txt = (
        f"📋 <b>API 模板列表</b>\n"
        f"━━━━━━━━━━━━━━━\n\n"
        f"共 {len(templates)} 个模板\n\n"
        f"💡 <b>使用变量</b>:\n"
        f"• <code>{{service_id}}</code> - 服务ID\n"
        f"• <code>{{token}}</code> - API Token\n"
        f"• <code>{{current_ip}}</code> - 当前IP\n\n"
        f"<b>当前模板:</b>\n"
    )
    
    kb = []
    
    if templates:
        for t in templates:
            status = "✅" if t.get('enabled', True) else "❌"
            name = t.get('name', '未命名')
            url = t.get('url', '')
            url_short = url[:35] + "..." if len(url) > 35 else url
            
            txt += f"{status} <b>{sanitize_html(name)}</b>\n   <code>{sanitize_html(url_short)}</code>\n\n"
            
            kb.append([
                InlineKeyboardButton(
                    f"{'❌ 禁用' if t.get('enabled', True) else '✅ 启用'} {name[:15]}",
                    callback_data=f"ip_api_toggle_{t['id']}"
                ),
                InlineKeyboardButton("🗑️", callback_data=f"ip_api_del_{t['id']}")
            ])
            kb.append([
                InlineKeyboardButton(f"▶️ 执行 {name[:15]}", callback_data=f"ip_api_run_{t['id']}")
            ])
    else:
        txt += "📭 暂无模板，请添加"
    
    kb.append([InlineKeyboardButton("➕ 添加新模板", callback_data="ip_api_add")])
    kb.append([InlineKeyboardButton("🔙 返回", callback_data="ip_mon_menu")])
    
    return txt, InlineKeyboardMarkup(kb)

def get_shared_settings_menu():
    """构建共享参数设置菜单"""
    conf = load_config()
    service_id = conf.get('api_service_id', '')
    token = conf.get('api_token', '')
    
    # 隐藏 token
    token_display = token[:4] + "****" + token[-4:] if len(token) > 8 else "****" if token else "未设置"
    
    txt = (
        f"⚙️ <b>共享参数设置</b>\n"
        f"━━━━━━━━━━━━━━━\n\n"
        f"这些参数会被所有 API 模板使用:\n\n"
        f"🔑 <b>Service ID</b>: <code>{service_id or '未设置'}</code>\n"
        f"🔐 <b>Token</b>: <code>{token_display}</code>\n"
        f"📡 <b>当前 IP</b>: <code>{get_current_ip()}</code>\n\n"
        f"━━━━━━━━━━━━━━━\n"
        f"💡 在模板 URL 中使用 <code>{{service_id}}</code> 和 <code>{{token}}</code> 引用"
    )
    
    kb = [
        [InlineKeyboardButton("🔑 设置 Service ID", callback_data="ip_share_set_sid")],
        [InlineKeyboardButton("🔐 设置 Token", callback_data="ip_share_set_token")],
        [InlineKeyboardButton("🔙 返回", callback_data="ip_mon_menu")]
    ]
    
    return txt, InlineKeyboardMarkup(kb)

def format_api_response(data):
    """格式化 API 响应"""
    if isinstance(data, dict):
        lines = []
        for k, v in data.items():
            if k == 'raw':
                lines.append(f"<code>{sanitize_html(str(v)[:300])}</code>")
            else:
                lines.append(f"• {sanitize_html(str(k))}: <code>{sanitize_html(str(v))}</code>")
        return "\n".join(lines)
    else:
        return f"<code>{sanitize_html(str(data)[:500])}</code>"
