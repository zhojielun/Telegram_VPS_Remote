# -*- coding: utf-8 -*-
# modules/network.py (V6.0.0 内网智能管理版 - 安全加固版)
import subprocess, re, os, requests, math, ipaddress, netifaces, html, json
from datetime import datetime
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from config import load_ports, save_ports, SSH_FILE, load_config

# 导入安全模块
from security import safe_subprocess_run, validate_port, validate_ip, validate_cidr

# --- 辅助: IP 信息缓存 ---
IP_CACHE = {}

def get_flag_emoji(country_code):
    """将国家代码转换为旗帜 Emoji"""
    if not country_code or len(country_code) != 2:
        return "🇺🇳"
    return "".join([chr(ord(c.upper()) + 127397) for c in country_code])

def get_ip_detail(ip):
    """获取 IP 详细信息 (带缓存)"""
    query_ip = ip.split('/')[0] if '/' in ip else ip
    
    if query_ip in IP_CACHE:
        return IP_CACHE[query_ip]
    
    try:
        url = f"http://ip-api.com/json/{query_ip}?fields=status,message,countryCode,isp"
        r = requests.get(url, timeout=1.5).json()
        
        if r.get('status') == 'success':
            flag = get_flag_emoji(r.get('countryCode'))
            isp = r.get('isp', 'Unknown')
            if len(isp) > 15:
                isp = isp[:15] + "..."
            info = {'flag': flag, 'isp': isp, 'code': r.get('countryCode')}
        else:
            info = {'flag': "🏴‍☠️", 'isp': "Private", 'code': "XX"}
        
        IP_CACHE[query_ip] = info
        return info
    except:
        return {'flag': "📡", 'isp': "Timeout", 'code': "XX"}

def get_ssh_port():
    """增强的 SSH 端口检测"""
    try:
        out = subprocess.getoutput("sshd -T 2>/dev/null | grep '^port '").strip()
        if out and 'port' in out.lower():
            port = out.split()[-1]
            if port.isdigit():
                return port
    except:
        pass
    
    try:
        if os.path.exists(SSH_FILE):
            out = subprocess.getoutput(f"grep -i '^Port ' {SSH_FILE}").strip()
            if out:
                port = out.split()[-1]
                if port.isdigit():
                    return port
    except:
        pass
    
    return "22"

# ===============================
# 🏠 内网智能管理 (核心新增)
# ===============================

def detect_local_networks():
    """
    智能检测本机所有网段
    返回: [{'network': '192.168.1.0/24', 'interface': 'eth0', 'type': 'current', 'ip': '192.168.1.100'}]
    """
    networks = []
    detected_networks = set()
    
    # 标准私网段
    STANDARD_PRIVATE = [
        {'network': '10.0.0.0/8', 'type': 'standard'},
        {'network': '172.16.0.0/12', 'type': 'standard'},
        {'network': '192.168.0.0/16', 'type': 'standard'},
        {'network': '127.0.0.0/8', 'type': 'loopback'}
    ]
    
    try:
        # 遍历所有网卡
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addrs:
                    continue
                
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    
                    if not ip or not netmask:
                        continue
                    
                    # 跳过非私网IP
                    if not ipaddress.ip_address(ip).is_private and ip != '127.0.0.1':
                        continue
                    
                    # 计算网段
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    network_str = str(network)
                    
                    # 避免重复
                    if network_str in detected_networks:
                        continue
                    
                    detected_networks.add(network_str)
                    
                    # 判断类型
                    if 'docker' in iface.lower():
                        net_type = 'docker'
                    elif 'tun' in iface.lower() or 'tap' in iface.lower() or 'vpn' in iface.lower():
                        net_type = 'vpn'
                    elif 'tailscale' in iface.lower() or 'wg' in iface.lower():
                        net_type = 'vpn'
                    elif ip.startswith('127.'):
                        net_type = 'loopback'
                    else:
                        net_type = 'current'
                    
                    networks.append({
                        'network': network_str,
                        'interface': iface,
                        'type': net_type,
                        'ip': ip
                    })
            except:
                continue
        
        # 添加标准私网段 (如果未检测到)
        for std in STANDARD_PRIVATE:
            if std['network'] not in detected_networks:
                networks.append({
                    'network': std['network'],
                    'interface': 'N/A',
                    'type': std['type'],
                    'ip': 'N/A'
                })
    
    except Exception as e:
        print(f"⚠️ 网段检测异常: {e}")
        # 降级方案: 返回标准私网段
        return STANDARD_PRIVATE
    
    return networks

def check_network_status(network):
    """
    检查某个网段是否已放行
    返回: True (已放行) / False (未放行)
    """
    try:
        # 验证网络格式
        if not validate_cidr(network):
            return False
        
        # 使用 iptables 命令检查规则
        result = safe_subprocess_run(
            ["iptables", "-S", "INPUT"],
            timeout=5
        )
        
        if result.returncode != 0:
            return False
        
        output = result.stdout.decode('utf-8', errors='ignore')
        # 检查是否有 ACCEPT 规则
        pattern = f'-A INPUT -s {network} .*-j ACCEPT'
        return bool(re.search(pattern, output))
    except:
        return False

def toggle_network_access(network):
    """
    切换网段的访问权限 - 安全加固版
    """
    try:
        # 验证网络格式
        if not validate_cidr(network):
            return "❌ 无效的网段格式"
        
        is_allowed = check_network_status(network)
        
        if is_allowed:
            # 当前已放行 → 拒绝
            result = safe_subprocess_run(
                ["iptables", "-D", "INPUT", "-s", network, "-j", "ACCEPT"],
                check=True
            )
            return f"❌ 已拒绝网段 <code>{network}</code>"
        else:
            # 当前已拒绝 → 放行
            result = safe_subprocess_run(
                ["iptables", "-I", "INPUT", "1", "-s", network, "-j", "ACCEPT"],
                check=True
            )
            return f"✅ 已放行网段 <code>{network}</code> (所有端口)"
    
    except Exception as e:
        return f"❌ 操作失败: {str(e)}"

def init_default_networks():
    """
    初始化默认网段规则 - 安全加固版
    在系统启动时调用,确保标准私网和Docker网段默认放行
    """
    networks = detect_local_networks()
    
    for net_info in networks:
        network = net_info['network']
        net_type = net_info['type']
        
        # 标准私网、Docker、VPN、本地回环 默认放行
        if net_type in ['standard', 'docker', 'vpn', 'loopback', 'current']:
            if not check_network_status(network):
                try:
                    # 验证网络格式后使用安全的命令执行
                    if validate_cidr(network):
                        safe_subprocess_run(
                            ["iptables", "-I", "INPUT", "1", "-s", network, "-j", "ACCEPT"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                except:
                    pass

def get_network_manage_menu():
    """
    构建内网访问管理菜单
    """
    networks = detect_local_networks()
    
    # 按类型排序: current > docker > vpn > standard > loopback
    type_priority = {'current': 1, 'docker': 2, 'vpn': 3, 'standard': 4, 'loopback': 5}
    networks.sort(key=lambda x: type_priority.get(x['type'], 99))
    
    txt = (f"🏠 <b>内网访问控制</b>\n"
           f"━━━━━━━━━━━━━━━\n"
           f"📡 检测到 {len(networks)} 个网段:\n\n")
    
    kb = []
    
    for net_info in networks:
        network = net_info['network']
        iface = net_info['interface']
        net_type = net_info['type']
        ip = net_info.get('ip', 'N/A')
        
        # 检查状态
        is_allowed = check_network_status(network)
        
        # 图标
        if is_allowed:
            icon = "✅"
        else:
            icon = "❌"
        
        # 类型标签
        if net_type == 'current':
            type_label = "当前网段"
        elif net_type == 'docker':
            type_label = "Docker"
        elif net_type == 'vpn':
            type_label = "VPN"
        elif net_type == 'loopback':
            type_label = "本地"
        elif net_type == 'standard':
            type_label = "标准私网"
        else:
            type_label = "其他"
        
        # 详情文本
        if ip != 'N/A':
            txt += f"{icon} <code>{network}</code> ({type_label})\n   网卡: {iface} | IP: {ip}\n\n"
        else:
            txt += f"{icon} <code>{network}</code> ({type_label})\n\n"
        
        # 按钮
        kb.append([InlineKeyboardButton(
            f"{icon} {network} ({type_label})",
            callback_data=f"net_lan_{network.replace('/', '_')}"
        )])
    
    txt += (f"━━━━━━━━━━━━━━━\n"
            f"💡 <b>说明</b>:\n"
            f"• ✅ = 已放行 (所有端口可访问)\n"
            f"• ❌ = 已拒绝\n"
            f"• 标准私网默认开启\n"
            f"• Docker/VPN 自动识别并放行")
    
    kb.append([InlineKeyboardButton("🔄 重新检测", callback_data="net_lan_refresh")])
    kb.append([InlineKeyboardButton("➕ 手动添加网段", callback_data="net_lan_add")])
    kb.append([InlineKeyboardButton("🔙 返回端口配电箱", callback_data="net_ports")])
    
    return txt, InlineKeyboardMarkup(kb)

# ===============================
# 🚪 端口控制 (保持原有逻辑)
# ===============================

def build_port_menu():
    """构建端口控制菜单"""
    sp = get_ssh_port()
    sc = "ACCEPT" in subprocess.getoutput(f"iptables -L INPUT -n | grep 'dpt:{sp}'")
    pc = "DROP" in subprocess.getoutput("iptables -L INPUT -n | grep 'icmp'")
    fw_res = subprocess.getoutput(r"iptables -S INPUT | grep '\-P INPUT'")
    is_wl = "DROP" in fw_res
    
    biz = load_ports()
    btns = []
    for p, i in biz.items():
        status = "🟢" if f"dpt:{p}" in subprocess.getoutput("iptables -L INPUT -n") else "🔴"
        desc = i.get('desc', '端口')
        btns.append(InlineKeyboardButton(f"{status} {desc}({p})", callback_data=f"net_biz_{p}"))
    
    kb = [
        [InlineKeyboardButton(f"{'🟢' if sc else '🔴'} SSH公网 ({sp})", callback_data=f"net_ssh_{sp}")],
        [InlineKeyboardButton(f"{'🔴' if pc else '🟢'} 允许 Ping", callback_data="net_ping")]
    ]
    kb.extend([btns[i:i+2] for i in range(0, len(btns), 2)])
    
    # ✅ 新增: 内网访问管理按钮
    kb.append([InlineKeyboardButton("🏠 内网访问管理", callback_data="net_lan_manage")])
    
    kb.append([
        InlineKeyboardButton("🛡️ 激活白名单" if not is_wl else "🛡️ 白名单模式 ✅", callback_data="net_reset"), 
        InlineKeyboardButton("🔓 开放所有端口" if is_wl else "🔓 全开放 ✅", callback_data="net_rescue")
    ])
    kb.append([
        InlineKeyboardButton("➕ 添加端口", callback_data="net_add"), 
        InlineKeyboardButton("➖ 删除端口", callback_data="net_del")
    ])
    kb.append([InlineKeyboardButton("🔙 返回", callback_data="back")])
    
    return (
        "🚪 <b>端口配电箱</b>\n"
        "━━━━━━━━━━━━━━━\n"
        "🟢=开放 | 🔴=关闭\n"
        "💡 <b>提示</b>: 内网访问请进入 🏠内网管理\n\n"
        "🛡️ <b>白名单模式</b>: 开启后,未列出的端口将无法访问 (SSH除外)。"
    ), InlineKeyboardMarkup(kb)

def toggle_port(port):
    """切换端口开关 (仅控制外网) - 安全加固版"""
    try:
        # 验证端口格式
        if not validate_port(port):
            return "❌ 无效的端口号"
        
        # 检查规则是否存在
        check_result = safe_subprocess_run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
            timeout=5
        )
        
        if check_result.returncode != 0:
            # 规则不存在，添加
            safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
            safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"])
            return f"🟢 端口 {port} 已开放"
        else:
            # 规则存在，删除
            safe_subprocess_run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
            safe_subprocess_run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"])
            return f"🔴 端口 {port} 已关闭"
    except Exception as e:
        return f"❌ 操作失败: {e}"

def add_port_rule(port_str):
    """添加端口规则 - 安全加固版"""
    try:
        parts = port_str.split()
        port = parts[0]
        desc = parts[1] if len(parts) > 1 else "自定义"
        
        # 验证端口格式
        if not validate_port(port):
            return "❌ 端口号无效 (1-65535)"
        
        # 保存端口信息
        biz = load_ports()
        biz[port] = {'desc': desc}
        save_ports(biz)
        
        # 使用安全的命令执行
        safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
        safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"])
        
        return f"✅ 端口 {port} ({desc}) 已添加并开放"
    except Exception as e:
        return f"❌ 添加失败: {e}"

def del_port_rule(port):
    """删除端口规则 - 安全加固版"""
    try:
        # 验证端口格式
        if not validate_port(port):
            return "❌ 端口号无效 (1-65535)"
        
        biz = load_ports()
        if port not in biz:
            return "⚠️ 端口不在列表中"
        
        del biz[port]
        save_ports(biz)
        
        # 使用安全的命令执行
        safe_subprocess_run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
        safe_subprocess_run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"])
        
        return f"🗑️ 端口 {port} 已移除"
    except Exception as e:
        return f"❌ 删除失败: {e}"

def toggle_ssh(port):
    """切换 SSH 端口开关 - 安全加固版"""
    try:
        # 验证端口格式
        if not validate_port(port):
            return "❌ 无效的端口号"
        
        # 检查规则是否存在
        check_result = safe_subprocess_run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
            timeout=5
        )
        
        if check_result.returncode != 0:
            # 规则不存在，添加
            safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
            return "🟢 SSH 端口已允许"
        else:
            # 规则存在，删除
            safe_subprocess_run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
            return "🔴 SSH 端口已从白名单移除"
    except Exception as e:
        return f"❌ 操作失败: {e}"

def toggle_ping():
    """切换 Ping 开关 - 安全加固版"""
    try:
        # 检查规则是否存在
        check_result = safe_subprocess_run(
            ["iptables", "-C", "INPUT", "-p", "icmp", "-j", "DROP"],
            timeout=5
        )
        
        if check_result.returncode != 0:
            # 规则不存在，添加
            safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "icmp", "-j", "DROP"])
            return "🔴 已禁止 Ping (隐身模式)"
        else:
            # 规则存在，删除
            safe_subprocess_run(["iptables", "-D", "INPUT", "-p", "icmp", "-j", "DROP"])
            return "🟢 已允许 Ping"
    except Exception as e:
        return f"❌ 操作失败: {e}"

def set_whitelist_mode(enable=True):
    """设置白名单模式 - 安全加固版"""
    try:
        if enable:
            sp = get_ssh_port()
            safe_subprocess_run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", sp, "-j", "ACCEPT"])
            safe_subprocess_run(["iptables", "-I", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            safe_subprocess_run(["iptables", "-I", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            
            # 确保内网规则优先
            init_default_networks()
            
            safe_subprocess_run(["iptables", "-P", "INPUT", "DROP"])
            return "🛡️ 白名单模式已激活!"
        else:
            safe_subprocess_run(["iptables", "-P", "INPUT", "ACCEPT"])
            return "🔓 防火墙已全开放"
    except Exception as e:
        return f"❌ 设置失败: {e}"

# ===============================
# 📊 流量可视化 (增强版)
# ===============================

def generate_traffic_bar(value_gb, max_val):
    """生成流量进度条"""
    if max_val == 0:
        max_val = 1
    percent = min(value_gb / max_val, 1.0)
    filled = int(percent * 10)
    
    if value_gb < 0.1:
        icon = "░"
    elif value_gb < 0.5:
        icon = "▒"  
    elif value_gb < 1:
        icon = "▓"
    else:
        icon = "█"
    
    return icon * filled + "░" * (10 - filled)

def parse_traffic_value(traffic_str):
    """解析流量字符串为 GB 数值"""
    try:
        parts = traffic_str.split()
        val = float(parts[0])
        unit = parts[1].lower()
        
        if 'gib' in unit or 'gb' in unit:
            return val
        elif 'mib' in unit or 'mb' in unit:
            return val / 1024
        elif 'kib' in unit or 'kb' in unit:
            return val / 1048576
        else:
            return val
    except:
        return 0.0

def get_traffic_hourly():
    """获取小时流量趋势"""
    conf = load_config()
    raw = subprocess.getoutput("vnstat -h 24")
    lines = raw.split('\n')
    max_traffic = 0.01
    temp_data = []
    
    for line in lines:
        match = re.search(r'(\d{2}:\d{2})\s+([\d\.]+\s+\w+iB)\s+\|\s+([\d\.]+\s+\w+iB)\s+\|\s+([\d\.]+\s+\w+iB)', line)
        if match:
            time_str, rx, tx, total = match.group(1), match.group(2), match.group(3), match.group(4)
            total_gb = parse_traffic_value(total)
            max_traffic = max(max_traffic, total_gb)
            temp_data.append({
                'time': time_str, 
                'rx': rx, 
                'tx': tx, 
                'total': total, 
                'total_gb': total_gb
            })
    
    hourly_data = []
    for data in temp_data:
        bar = generate_traffic_bar(data['total_gb'], max_traffic)
        
        if data['total_gb'] > 1:
            emoji = "🔥"
        elif data['total_gb'] > 0.5:
            emoji = "🟠"
        elif data['total_gb'] > 0.1:
            emoji = "🟡"
        else:
            emoji = "🟢"
        
        hourly_data.append(f"<code>{data['time']}</code> {bar} {emoji} <code>{data['total'].split()[0]}{data['total'].split()[1][0]}</code>")
    
    today_total = sum([d['total_gb'] for d in temp_data])
    
    res = f"📊 <b>流量审计 · 24H 可视化趋势</b>\n🌐 节点: <code>{conf.get('server_remark', 'MyVPS')}</code>\n━━━━━━━━━━━━━━━\n"
    res += "\n".join(hourly_data[-12:]) if hourly_data else "🔭 暂无数据"
    res += f"\n━━━━━━━━━━━━━━━\n📊 今日累计: <code>{today_total:.2f} GB</code>\n💡 🟢&lt;100M | 🟡&lt;500M | 🟠&lt;1G | 🔥&gt;1G"
    
    status_icon = "✅" if conf.get('traffic_daily_report') else "❌"
    
    kb = [
        [InlineKeyboardButton("⏳ 小时趋势 (现)", callback_data="sys_traffic_h"), 
         InlineKeyboardButton("📅 30日账单", callback_data="sys_traffic_d"), 
         InlineKeyboardButton("🐳 实时监控", callback_data="sys_traffic_r")],
        [InlineKeyboardButton("📈 Docker流量", callback_data="sys_traffic_rank"),
         InlineKeyboardButton(f"{status_icon} 流量日报", callback_data="sys_traffic_report_toggle")],
        [InlineKeyboardButton("🔄 刷新", callback_data="sys_traffic_h"), 
         InlineKeyboardButton("🔙 返回", callback_data="back")]
    ]
    
    return res, InlineKeyboardMarkup(kb)

def get_daily_traffic_report():
    """生成每日流量日报"""
    conf = load_config()
    import modules.system as sys_mod
    
    # 获取今日流量 (从 vnstat 读取 JSON)
    rx, tx, total = 0.0, 0.0, 0.0
    try:
        raw = subprocess.check_output(["vnstat", "-d", "1", "--json"], stderr=subprocess.DEVNULL).decode('utf-8')
        data = json.loads(raw)['interfaces']
        
        # 找到主网卡
        target_iface = None
        max_t = -1
        for iface in data:
            if iface['name'] == 'lo': continue
            curr_t = iface['traffic']['total']['rx'] + iface['traffic']['total']['tx']
            if curr_t > max_t:
                max_t = curr_t
                target_iface = iface
        
        if target_iface:
            # 获取最后一天的记录 (通常是今天)
            day_data = target_iface['traffic']['day'][-1]
            rx = day_data['rx'] / 1024**3
            tx = day_data['tx'] / 1024**3
            total = rx + tx
    except:
        pass
        
    used_month = sys_mod.get_traffic_stats('month')
    limit = conf.get('traffic_limit_gb', 1000)
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    txt = (f"📊 <b>流量日报</b> 📊\n"
           f"━━━━━━━━━━━━━━━\n"
           f"🖥 服务器: <code>{conf.get('server_remark', 'MyVPS')}</code>\n"
           f"🕒 时间: <code>{now}</code>\n"
           f"⬇️ 下载: <code>{rx:.2f} GiB</code>\n"
           f"⬆️ 上传: <code>{tx:.2f} GiB</code>\n"
           f"💰 今日总计: <code>{total:.2f} GiB</code>\n"
           f"📊 月流量: <code>{used_month:.2f} G</code> / <code>{limit} G</code>")
    return txt

def get_traffic_history():
    """获取流量历史账单 (方案 C 增强版: 图形化对比)"""
    conf = load_config()
    # 使用 JSON 模式获取精确数值
    raw = subprocess.getoutput("vnstat -d 30 --json")
    history_blocks = []
    
    try:
        data = json.loads(raw)['interfaces']
        # 找到主网卡
        target_iface = None
        max_t = -1
        for iface in data:
            if iface['name'] == 'lo': continue
            curr_t = iface['traffic']['total']['rx'] + iface['traffic']['total']['tx']
            if curr_t > max_t:
                max_t = curr_t
                target_iface = iface
        
        if target_iface:
            traffic_days = target_iface['traffic']['day']
            
            # 计算这 30 天内的最高流量，用于生成相对比例的进度条
            daily_totals = [d['rx'] + d['tx'] for d in traffic_days]
            max_daily_bytes = max(daily_totals) if daily_totals else 1
            
            # 反转列表，从今天开始往回显示
            for day in reversed(traffic_days):
                d = day['date']
                date_str = f"{d['year']}-{d['month']:02d}-{d['day']:02d}"
                rx_bytes = day['rx']
                tx_bytes = day['tx']
                total_bytes = rx_bytes + tx_bytes
                
                rx_gb = rx_bytes / 1024**3
                tx_gb = tx_bytes / 1024**3
                total_gb = total_bytes / 1024**3
                
                # 单位换算辅助函数
                def fmt(gb):
                    return f"{gb:.2f}G" if gb >= 1 else f"{gb*1024:.0f}M"

                # 生成进度条 (10格)
                percent = total_bytes / max_daily_bytes
                filled = int(percent * 10)
                bar = "█" * filled + "░" * (10 - filled)
                
                # 状态标签
                if total_gb > 5: emoji = "🔥"
                elif total_gb > 1: emoji = "🟡"
                else: emoji = "🟢"
                
                block = (f"🕒 <code>{date_str}</code> <code>{bar}</code> {fmt(total_gb)} {emoji}\n"
                         f"┕ ↓ <code>{fmt(rx_gb)}</code> | ↑ <code>{fmt(tx_gb)}</code>")
                history_blocks.append(block)
    except:
        return "❌ 流量数据解析失败", None

    res = f"📈 <b>30日流量波动分布</b>\n━━━━━━━━━━━━━━━\n"
    # 只显示最近10天以免消息过长
    res += "\n\n".join(history_blocks[:10]) if history_blocks else "🔭 暂无历史账单"
    res += f"\n━━━━━━━━━━━━━━━\n💡 🟢&lt;1G | 🟡&lt;5G | 🔥&gt;5G"
    
    kb = [
        [InlineKeyboardButton("⏳ 小时趋势", callback_data="sys_traffic_h"), 
         InlineKeyboardButton("📅 30日账单 (现)", callback_data="sys_traffic_d"), 
         InlineKeyboardButton("🐳 实时监控", callback_data="sys_traffic_r")],
        [InlineKeyboardButton("🔄 刷新", callback_data="sys_traffic_d"), 
         InlineKeyboardButton("🔙 返回", callback_data="back")]
    ]
    
    return res, InlineKeyboardMarkup(kb)

def get_traffic_realtime():
    """获取实时流量监控"""
    # Docker 容器流量
    dk_raw = subprocess.getoutput(r"docker stats --no-stream --format '{{.Name}}|{{.NetIO}}'")
    dk_usage = [f"🐳 {line.split('|')[0].ljust(12)} | {line.split('|')[1]}" 
                for line in dk_raw.split('\n') if '|' in line]
    
    # nethogs 进程监控 (移除sudo)
    nethogs_cmd = "timeout 3 nethogs -t -c 2 2>/dev/null || echo 'nethogs_unavailable'"
    nethogs_raw = subprocess.getoutput(nethogs_cmd)
    
    process_dict = {}
    
    if 'nethogs_unavailable' not in nethogs_raw:
        for line in nethogs_raw.split('\n'):
            if '/' in line:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        proc_name = parts[0].split('/')[-1]
                        s, r = float(parts[-2]), float(parts[-1])
                        if proc_name in process_dict:
                            process_dict[proc_name]['s'] += s
                            process_dict[proc_name]['r'] += r
                        else:
                            process_dict[proc_name] = {'s': s, 'r': r}
                    except:
                        continue
    
    app_usage = []
    sorted_apps = sorted(process_dict.items(), key=lambda x: x[1]['s'] + x[1]['r'], reverse=True)
    
    for name, flow in sorted_apps[:5]:
        if flow['s'] > 0 or flow['r'] > 0:
            app_usage.append(f"📦 {name.ljust(12)} | ⬆️{flow['s']:.1f} ⬇️{flow['r']:.1f} KB/s")

    import html
    res = f"📊 <b>流量审计 · 实时监控</b>\n━━━━━━━━━━━━━━━\n🐳 <b>容器网络 I/O (实时)</b>:\n<pre>\n"
    res += html.escape("\n".join(dk_usage) if dk_usage else "无活跃容器") + "\n</pre>\n"
    res += "<b>🔥 进程带宽占用 (TOP 5)</b>:\n<pre>\n"
    res += html.escape("\n".join(app_usage) if app_usage else "暂无活跃进程流量") + "\n</pre>\n"
    res += "💡 <i>实时采样中...</i>"
    
    kb = [
        [InlineKeyboardButton("⏳ 小时趋势", callback_data="sys_traffic_h"), 
         InlineKeyboardButton("📅 30日账单", callback_data="sys_traffic_d"), 
         InlineKeyboardButton("🐳 实时监控 (现)", callback_data="sys_traffic_r")],
        [InlineKeyboardButton("🔄 刷新", callback_data="sys_traffic_r"), 
         InlineKeyboardButton("🔙 返回", callback_data="back")]
    ]
    
    return res, InlineKeyboardMarkup(kb)

def get_traffic_ranking():
    """获取 Docker 容器流量排行"""
    conf = load_config()
    
    try:
        dk_raw = subprocess.getoutput(r"docker stats --no-stream --format '{{.Name}}|{{.NetIO}}'")
        container_traffic = []
        
        for line in dk_raw.split('\n'):
            if '|' not in line:
                continue
            parts = line.split('|')
            name = parts[0]
            net_io = parts[1]
            
            try:
                io_parts = net_io.split('/')
                rx_str = io_parts[0].strip()
                tx_str = io_parts[1].strip()
                rx_gb = parse_traffic_value(rx_str)
                tx_gb = parse_traffic_value(tx_str)
                total = rx_gb + tx_gb
                container_traffic.append({
                    'name': name, 
                    'rx': rx_gb, 
                    'tx': tx_gb, 
                    'total': total
                })
            except:
                continue
        
        container_traffic.sort(key=lambda x: x['total'], reverse=True)
    except:
        container_traffic = []
    
    txt = f"📈 <b>Docker 流量排行榜</b>\n━━━━━━━━━━━━━━━\n\n"
    
    if container_traffic:
        txt += "<b>🐳 容器流量统计</b> (自启动以来):\n"
        for idx, c in enumerate(container_traffic[:8], 1):
            bar = generate_traffic_bar(c['total'], container_traffic[0]['total'])
            txt += f"<code>{idx}.</code> {bar} <code>{c['name'][:15]}</code>\n"
            txt += f"    ↓ {c['rx']:.2f}G  ↑ {c['tx']:.2f}G  💰 {c['total']:.2f}G\n"
    else:
        txt += "⚠️ 暂无容器流量数据\n"
    
    txt += "\n💡 <b>注意</b>: 容器流量统计从容器启动时开始计算"
    
    kb = [
        [InlineKeyboardButton("⏳ 小时趋势", callback_data="sys_traffic_h"),
         InlineKeyboardButton("📅 30日账单", callback_data="sys_traffic_d")],
        [InlineKeyboardButton("🔄 刷新", callback_data="sys_traffic_rank"),
         InlineKeyboardButton("🔙 返回", callback_data="back")]
    ]
    
    return txt, InlineKeyboardMarkup(kb)

    # ==================== 临时修复: 补全缺失函数 ====================

def get_all_bans():
    """获取所有黑名单规则"""
    raw = subprocess.getoutput("iptables -S INPUT")
    bans = []
    pattern = re.compile(r'-A INPUT -s ([\d\./]+) .*?-j DROP')
    for line in raw.split('\n'):
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            if ip == "0.0.0.0/0":
                continue
            bans.append(ip)
    return bans[::-1]

def get_ban_list_view(page=0, search_query=None):
    """黑名单列表视图 (完全增强版 - 显示IP地理信息+封禁原因)"""
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    from config import AUDIT_FILE
    import os
    
    all_bans = get_all_bans()
    
    if search_query:
        filtered_bans = [ip for ip in all_bans if search_query in ip]
        title_suffix = f"🔍 '{search_query}'"
    else:
        filtered_bans = all_bans
        title_suffix = f"共 {len(all_bans)} 个"
    
    PER_PAGE = 6
    total_pages = math.ceil(len(filtered_bans) / PER_PAGE) if filtered_bans else 1
    page = min(page, total_pages - 1) if total_pages > 0 else 0
    
    start_idx = page * PER_PAGE
    current_bans = filtered_bans[start_idx : start_idx + PER_PAGE]
    
    # 读取审计日志,建立IP->封禁信息的映射
    ban_reasons = {}
    if os.path.exists(AUDIT_FILE):
        try:
            with open(AUDIT_FILE, 'r', encoding='utf-8') as f:
                for line in f.readlines()[-200:]:  # 只读最近200行
                    if '自动封禁' in line or '手动封禁' in line:
                        # 格式: [2025-01-28 10:30:45] [SENTINEL] 自动封禁: IP: 1.2.3.4, 失败次数: 8
                        import re
                        time_match = re.search(r'\[([\d\-: ]+)\]', line)
                        ip_match = re.search(r'IP:\s*([\d\.]+)', line)
                        count_match = re.search(r'失败次数:\s*(\d+)', line)
                        
                        if time_match and ip_match:
                            timestamp = time_match.group(1)
                            ip = ip_match.group(1)
                            count = count_match.group(1) if count_match else "未知"
                            
                            if '自动封禁' in line:
                                reason = f"SSH暴力破解 ({count}次失败)"
                            else:
                                reason = "手动封禁"
                            
                            ban_reasons[ip] = {
                                'time': timestamp,
                                'reason': reason
                            }
        except:
            pass
    
    txt = f"🚫 <b>黑名单堡垒</b> ({title_suffix}) | 第 {page+1}/{total_pages} 页\n━━━━━━━━━━━━━━━\n"
    if not current_bans:
        txt += "✅ 天下太平,黑名单为空。"
    else:
        txt += "\n"
    
    # 显示黑名单详情
    for idx, ip in enumerate(current_bans):
        # 获取IP详细信息
        ip_info = get_ip_detail(ip)
        flag = ip_info.get('flag', '🏴‍☠️')
        isp = ip_info.get('isp', 'Unknown')
        
        txt += f"<code>{start_idx+idx+1}.</code> 🔴 <code>{ip}</code>\n"
        txt += f"    {flag} {isp}\n"
        
        # 显示封禁原因和时间
        if ip in ban_reasons:
            info = ban_reasons[ip]
            txt += f"    ⚠️ {info['reason']}\n"
            txt += f"    🕐 {info['time']}\n"
        else:
            txt += f"    💡 历史封禁(审计日志已过期)\n"
        
        txt += "\n"
    
    # 添加操作按钮
    kb = [
        [InlineKeyboardButton("➕ 手动封禁", callback_data="ban_add"),
         InlineKeyboardButton("➖ 解封IP", callback_data="ban_del")],
        [InlineKeyboardButton("♻️ 清空黑名单", callback_data="ban_reset")]
    ]
    
    # 分页按钮
    if total_pages > 1:
        nav = []
        if page > 0:
            nav.append(InlineKeyboardButton("⬅️ 上页", callback_data=f"ban_page_{page-1}"))
        nav.append(InlineKeyboardButton(f"{page+1}/{total_pages}", callback_data=f"ban_page_{page}"))
        if page < total_pages - 1:
            nav.append(InlineKeyboardButton("下页 ➡️", callback_data=f"ban_page_{page+1}"))
        kb.append(nav)
    
    kb.append([InlineKeyboardButton("🔙 返回工具箱", callback_data="tool_box")])
    return txt, InlineKeyboardMarkup(kb)

def get_ghost_process_view():
    """扫鬼行动 · 一级菜单 (进程概览)"""
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    raw = subprocess.getoutput("ss -ntp | grep ESTAB")
    lines = raw.split('\n')
    proc_map = {}
    
    for line in lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 6:
            # 提取进程名
            m = re.search(r'\("([^"]+)"', parts[5])
            p_name = m.group(1) if m else "未知"
            # 过滤回环地址
            remote_ip = parts[4].rsplit(':', 1)[0].replace('[', '').replace(']', '')
            if remote_ip in ["127.0.0.1", "::1"]:
                continue
            proc_map[p_name] = proc_map.get(p_name, 0) + 1
    
    txt = "🕵️ <b>扫鬼行动 · 进程概览</b>\n━━━━━━━━━━━━━━━\n"
    kb = []
    
    if not proc_map:
        txt += "✅ 无活跃连接。"
    else:
        for p, c in proc_map.items():
            kb.append([InlineKeyboardButton(f"📦 {p}: {c} 个连接", callback_data=f"ghost_detail_{p}_0")])
    
    kb.append([InlineKeyboardButton("🔄 刷新", callback_data="tool_ghost")])
    kb.append([InlineKeyboardButton("🔙 返回工具箱", callback_data="tool_box")])
    return txt, InlineKeyboardMarkup(kb)

def get_ghost_detail_view(proc_name, page=0):
    """扫鬼行动 · 二级菜单 (进程连接详情 + 翻页)"""
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    raw = subprocess.getoutput("ss -ntp | grep ESTAB")
    lines = raw.split('\n')
    
    ips = []
    for line in lines:
        if not line.strip(): continue
        parts = line.split()
        if len(parts) >= 6 and f'"{proc_name}"' in parts[5]:
            remote_ip = parts[4].rsplit(':', 1)[0].replace('[', '').replace(']', '')
            if remote_ip not in ["127.0.0.1", "::1"]:
                ips.append(remote_ip)
    
    # 去重
    unique_ips = sorted(list(set(ips)))
    PER_PAGE = 5
    total_pages = math.ceil(len(unique_ips) / PER_PAGE)
    start = page * PER_PAGE
    end = start + PER_PAGE
    current_ips = unique_ips[start:end]
    
    txt = (f"🕵️ <b>连接详情:</b> <code>{proc_name}</code>\n"
           f"━━━━━━━━━━━━━━━\n"
           f"第 {page+1}/{total_pages} 页 | 共 {len(unique_ips)} 个独立 IP\n\n")
    
    kb = []
    for ip in current_ips:
        info = get_ip_detail(ip)
        flag = info.get('flag', '🌐')
        txt += f"📍 {flag} <code>{ip}</code>\n"
        kb.append([InlineKeyboardButton(f"🚫 封禁 {ip}", callback_data=f"ghost_ban_ip_{proc_name}_{page}_{ip}")])
    
    # 翻页按钮
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ 上页", callback_data=f"ghost_detail_{proc_name}_{page-1}"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("下页 ➡️", callback_data=f"ghost_detail_{proc_name}_{page+1}"))
    if nav: kb.append(nav)
    
    kb.append([InlineKeyboardButton("🔙 返回概览", callback_data="tool_ghost")])
    return txt, InlineKeyboardMarkup(kb)

def get_listen_text():
    """监听端口状态"""
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    raw = subprocess.getoutput("ss -ntlp | grep LISTEN")
    pub, loc = [], []
    
    for line in raw.split('\n'):
        if not line.strip():
            continue
        p = line.split()
        if len(p) < 4:
            continue
        adr, prt = p[3], p[3].split(':')[-1]
        proc = "未知"
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        
        info = f"{prt.ljust(6)} | {proc}"
        if "127.0.0.1" in adr or "::1" in adr:
            loc.append(info)
        else:
            pub.append(info)
    
    import html
    res = "📌 <b>监听状态</b>\n\n🌐 <b>公网</b>:\n<pre>\n" + html.escape("\n".join(pub) if pub else "无") + "\n</pre>\n"
    res += "<b>🔒 本地</b>:\n<pre>\n" + html.escape("\n".join(loc) if loc else "无") + "\n</pre>"
    
    return res, InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回工具箱", callback_data="tool_box")]])

def add_ban_manual(target):
    """手动添加黑名单 - 安全加固版"""
    try:
        # 验证 IP 或 CIDR 格式
        if not (validate_ip(target) or validate_cidr(target)):
            return "❌ 无效的 IP 或 CIDR 格式"
        
        # 检查是否已在黑名单中
        check_result = safe_subprocess_run(
            ["iptables", "-S", "INPUT"],
            timeout=5
        )
        
        if check_result.returncode == 0:
            output = check_result.stdout.decode('utf-8', errors='ignore')
            pattern = f'-A INPUT -s {target} .*-j DROP'
            if re.search(pattern, output):
                return f"⚠️ <code>{target}</code> 已在黑名单中"
        
        # 添加黑名单规则
        safe_subprocess_run(
            ["iptables", "-I", "INPUT", "1", "-s", target, "-j", "DROP"],
            check=True
        )
        return f"✅ 已封禁 <code>{target}</code>"
    except Exception as e:
        return f"❌ 操作失败: {e}"

def remove_ban_manual(target):
    """手动移除黑名单 - 安全加固版"""
    try:
        # 验证 IP 或 CIDR 格式
        if not (validate_ip(target) or validate_cidr(target)):
            return "❌ 无效的 IP 或 CIDR 格式"
        
        result = safe_subprocess_run(
            ["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"],
            timeout=5
        )
        
        if result.returncode == 0:
            return f"✅ 已解封 <code>{target}</code>"
        else:
            return "⚠️ 未找到规则"
    except Exception as e:
        return f"❌ 操作失败: {e}"

def reset_all_bans():
    """清空黑名单 - 安全加固版"""
    try:
        # 获取所有 DROP 规则
        result = safe_subprocess_run(
            ["iptables", "-S", "INPUT"],
            timeout=10
        )
        
        if result.returncode != 0:
            return "❌ 获取规则失败"
        
        output = result.stdout.decode('utf-8', errors='ignore')
        count = 0
        
        for line in output.split('\n'):
            if "-j DROP" in line and "-A INPUT" in line:
                # 解析并删除规则
                parts = line.strip().split()
                if len(parts) >= 4:
                    try:
                        # 从 -A INPUT ... -j DROP 提取参数
                        src_idx = parts.index('-s') if '-s' in parts else -1
                        if src_idx > 0 and src_idx + 1 < len(parts):
                            src = parts[src_idx + 1]
                            safe_subprocess_run(
                                ["iptables", "-D", "INPUT", "-s", src, "-j", "DROP"],
                                timeout=5
                            )
                            count += 1
                    except:
                        pass
        
        return f"♻️ 已清除 {count} 条规则"
    except Exception as e:
        return f"❌ 操作失败: {e}"
        return "❌ 操作失败"