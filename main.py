# -*- coding: utf-8 -*-
# main.py (V6.0.0 内网管理版 - 安全加固版)
import os, asyncio, logging, json, re, shutil
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# 导入安全模块
from security import (
    safe_shell_arg, safe_subprocess_run, validate_port, validate_ip,
    validate_filename, validate_path, validate_docker_name,
    validate_port_mapping, validate_volume_mapping, validate_env_var, sanitize_html
)

UPLOAD_DIR = "/var/lib/vps_bot/uploads"  # 上传文件目录
os.makedirs(UPLOAD_DIR, exist_ok=True)

from config import TOKEN, ALLOWED_USER_ID, ALLOWED_USER_IDS, load_config, save_config, load_ports, save_ports, SSH_FILE
import modules.network as net
import modules.system as sys_mod
import modules.docker_mgr as dk_mgr 
import modules.settings as settings_mod
import modules.backup as bk_mgr
import modules.health_check as health_mod
import modules.ip_monitor as ip_mon
from utils import get_audit_tail, log_audit

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

STATE = None 
SET_ACTION = None 
WIZARD_STATE = None
CURRENT_UPLOAD_DIR = UPLOAD_DIR # 默认上传目录
TEMP_API_NAME = ""  # 临时存储 API 模板名称

# --- 🚀 任务监控 ---
async def docker_sentinel(app: Application):
    """Docker 容器异常监控"""
    cmd = ["docker", "events", "--filter", "event=die", "--filter", "event=oom", "--format", "{{json .}}"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
        while True:
            line = await proc.stdout.readline()
            if not line: break
            try:
                event = json.loads(line.decode().strip())
                exit_code = event.get('Actor', {}).get('Attributes', {}).get('exitCode')
                if exit_code and exit_code != "0":
                    name = event.get('Actor', {}).get('Attributes', {}).get('name')
                    cid = event.get('id', '')[:12]
                    txt = f"🚨 <b>预警:容器异常停止</b>\n📦 容器: <code>{name}</code>\n📉 退出码: <code>{exit_code}</code>"
                    await app.bot.send_message(
                        chat_id=ALLOWED_USER_ID, 
                        text=txt, 
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("📄 查看", callback_data=f"dk_view_{cid}")]]), 
                        parse_mode="HTML"
                    )
            except: 
                continue
    except Exception as e:
        logging.error(f"Docker监控异常: {e}")

# --- 🎮 菜单 ---
async def start(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """主菜单"""
    if u.effective_user.id not in ALLOWED_USER_IDS: 
        return
    
    global STATE, WIZARD_STATE
    STATE = None
    WIZARD_STATE = None
    
    conf = load_config()
    used = sys_mod.get_traffic_stats('month')
    limit = conf.get('traffic_limit_gb', 1000)
    
    # 动态 UI 进度条
    perc = (used / limit * 100) if limit > 0 else 0
    filled = int(perc / 10)
    bar = f"{'▓' * filled}{'░' * (10 - filled)} {perc:.1f}%"
    
    kb = [
        [InlineKeyboardButton("📊 流量详情", callback_data="sys_traffic_h"), 
         InlineKeyboardButton("🌡️ 深度体检", callback_data="sys_report")],
        [InlineKeyboardButton("🚪 端口配电箱", callback_data="net_ports"), 
         InlineKeyboardButton("🐳 容器指挥官", callback_data="dk_m")],
        [InlineKeyboardButton("📤 备份 / 上传", callback_data="bk_menu"), 
         InlineKeyboardButton("🧰 工具箱", callback_data="tool_box")],
        [InlineKeyboardButton("🌐 IP 监控", callback_data="ip_mon_menu"),
         InlineKeyboardButton("⚙️ 实验室设置", callback_data="sent_lab")]
    ]
    
    txt = (f"🛸 <b>{conf.get('server_remark', 'X-Lab')} 控制台</b>\n"
           f"━━━━━━━━━━━━━━━\n"
           f"📈 月流量: <code>{used:.2f} G</code> / <code>{limit} G</code>\n"
           f"⌛️ 进度: <code>{bar}</code>\n"
           f"━━━━━━━━━━━━━━━\n"
           f"📂 上传目录: <code>{CURRENT_UPLOAD_DIR}</code>")
    
    if u.callback_query:
        await u.callback_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    else:
        await u.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def document_handler(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """处理用户发送的文件 - 安全加固版"""
    global STATE
    if u.effective_user.id not in ALLOWED_USER_IDS:
        return
    
    doc = u.message.document
    file_name = doc.file_name
    file_size = doc.file_size / 1024 / 1024
    
    # 安全检查：验证文件名，防止路径遍历
    is_valid, result = validate_filename(file_name)
    if not is_valid:
        await u.message.reply_text(f"❌ <b>文件名不安全:</b> {result}", parse_mode="HTML")
        return
    
    # 使用清理后的安全文件名
    safe_name = result
    file_size_mb = doc.file_size / 1024 / 1024
    
    # 检查文件大小限制 (最大 500MB)
    if file_size_mb > 500:
        await u.message.reply_text("❌ <b>文件过大:</b> 最大支持 500MB", parse_mode="HTML")
        return
    
    status_msg = await u.message.reply_text(
        f"📥 <b>开始接收文件:</b> <code>{sanitize_html(safe_name)}</code>\n"
        f"📊 大小: <code>{file_size_mb:.2f} MB</code>",
        parse_mode="HTML"
    )
    
    try:
        new_file = await c.bot.get_file(doc.file_id)
        
        # 使用安全路径拼接
        file_path = os.path.join(CURRENT_UPLOAD_DIR, safe_name)
        
        # 验证最终路径仍在上传目录内
        real_upload_dir = os.path.realpath(CURRENT_UPLOAD_DIR)
        real_file_path = os.path.realpath(file_path)
        if not real_file_path.startswith(real_upload_dir):
            await status_msg.edit_text("❌ <b>安全错误:</b> 文件路径异常", parse_mode="HTML")
            return
        
        await new_file.download_to_drive(file_path)
        
        await status_msg.edit_text(
            f"✅ <b>文件已送达!</b>\n"
            f"📂 存放在: <code>{sanitize_html(file_path)}</code>\n"
            f"📊 最终大小: <code>{file_size_mb:.2f} MB</code>",
            parse_mode="HTML"
        )
        
        # 自动切换回普通状态
        STATE = None
        
        # 如果是压缩包,提供解压建议
        if safe_name.endswith(('.zip', '.tar.gz', '.tar')):
            kb = [[InlineKeyboardButton("📦 立即解压", callback_data=f"tool_unzip_{safe_name}"),
                   InlineKeyboardButton("🔙 返回菜单", callback_data="back")]]
            await u.message.reply_text("💡 <b>检测到压缩包，是否需要解压？</b>", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        else:
            await start(u, c)
            
    except Exception as e:
        await status_msg.edit_text(f"❌ <b>传输中断:</b> <code>{sanitize_html(str(e))}</code>", parse_mode="HTML")

async def kk_command(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """KK 控制台"""
    if u.effective_user.id not in ALLOWED_USER_IDS: 
        return
    
    # 获取当前命令前缀
    from config import load_config
    conf = load_config()
    command_prefix = conf.get('command_prefix', 'kk')
    
    txt = f"🕹️ <b>{command_prefix.upper()} 远程控制台</b>\n━━━━━━━━━━━━━━━\n✅ 状态: 运行中 (PID: <code>{os.getpid()}</code>)"
    kb = [
        [InlineKeyboardButton("🏠 进入主页", callback_data="back")], 
        [InlineKeyboardButton("🔄 重启机器人", callback_data="sys_restart_bot")],
        [InlineKeyboardButton("📜 获取日志", callback_data="sys_get_log")]
    ]
    await u.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def settoken_command(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """直接设置TG Token命令"""
    if u.effective_user.id not in ALLOWED_USER_IDS: 
        return
    
    # 获取当前token
    from config import load_config
    conf = load_config()
    current_token = conf.get('bot_token', '未设置')
    
    # 检查是否有参数
    args = u.message.text.split()
    if len(args) < 2:
        await u.message.reply_text(
            f"🤖 <b>当前TG对接键</b>: <code>{current_token[:10]}...</code>\n\n"
            f"📝 <b>用法</b>: <code>/settoken 新Token</code>\n"
            f"💡 <b>格式</b>: <code>数字:字母数字组合</code>\n\n"
            f"⚠️ <b>注意</b>: 修改后需要重启机器人才能生效",
            parse_mode="HTML"
        )
        return
    
    new_token = args[1].strip()
    import re
    if not re.match(r'^\d+:[A-Za-z0-9_-]+$', new_token):
        await u.message.reply_text(
            "❌ <b>Token 格式错误</b>\n\n"
            "应为 '数字:字母数字组合' 格式，例如:\n"
            "<code>1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ</code>",
            parse_mode="HTML"
        )
        return
    
    # 更新配置
    conf['bot_token'] = new_token
    from config import save_config
    save_config(conf)
    
    # 获取当前命令前缀
    from config import load_config
    conf = load_config()
    command_prefix = conf.get('command_prefix', 'kk')
    
    await u.message.reply_text(
        f"✅ <b>TG对接键已更新</b>\n\n"
        f"新Token: <code>{new_token[:10]}...</code>\n\n"
        f"⚠️ <b>需要重启机器人才能生效</b>\n"
        f"请使用 /{command_prefix} 菜单中的 '🔄 重启机器人' 按钮",
        parse_mode="HTML"
    )

async def setadminid_command(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """直接设置管理员ID命令"""
    if u.effective_user.id not in ALLOWED_USER_IDS: 
        return
    
    # 获取当前admin id
    from config import load_config
    conf = load_config()
    current_admin_id = conf.get('admin_id', '未设置')
    
    # 检查是否有参数
    args = u.message.text.split()
    if len(args) < 2:
        await u.message.reply_text(
            f"👤 <b>当前管理员ID</b>: <code>{current_admin_id}</code>\n\n"
            f"📝 <b>用法</b>: <code>/setadminid 新管理员ID</code>\n"
            f"💡 <b>格式</b>: 纯数字 (例如: 12345678)\n"
            f"💡 <b>如何获取</b>: 在 Telegram 中发送 /id 给 @userinfobot\n\n"
            f"⚠️ <b>注意</b>: 修改后需要重启机器人才能生效",
            parse_mode="HTML"
        )
        return
    
    new_admin_id = args[1].strip()
    import re
    if not re.match(r'^\d+$', new_admin_id):
        await u.message.reply_text(
            "❌ <b>格式错误</b>\n\n"
            "管理员ID应为纯数字，例如:\n"
            "<code>12345678</code>",
            parse_mode="HTML"
        )
        return
    
    # 更新配置
    conf['admin_id'] = int(new_admin_id)
    from config import save_config
    save_config(conf)
    
    # 获取当前命令前缀
    from config import load_config
    conf = load_config()
    command_prefix = conf.get('command_prefix', 'kk')
    
    await u.message.reply_text(
        f"✅ <b>管理员ID已更新</b>\n\n"
        f"新管理员ID: <code>{new_admin_id}</code>\n\n"
        f"⚠️ <b>需要重启机器人才能生效</b>\n"
        f"请使用 /{command_prefix} 菜单中的 '🔄 重启机器人' 按钮",
        parse_mode="HTML"
    )

async def setprefix_command(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """直接设置命令前缀命令"""
    if u.effective_user.id not in ALLOWED_USER_IDS: 
        return
    
    # 获取当前前缀
    from config import load_config
    conf = load_config()
    current_prefix = conf.get('command_prefix', 'kk')
    
    # 检查是否有参数
    args = u.message.text.split()
    if len(args) < 2:
        await u.message.reply_text(
            f"🔤 <b>当前命令前缀</b>: <code>{current_prefix}</code>\n"
            f"📝 <b>当前命令</b>: <code>/{current_prefix}</code>\n\n"
            f"📝 <b>用法</b>: <code>/setprefix 新前缀</code>\n"
            f"💡 <b>格式</b>: 小写字母、数字、下划线 (3-20字符)\n"
            f"📝 <b>示例</b>: <code>vps1</code> → 命令变为 <code>/vps1</code>\n\n"
            f"⚠️ <b>重要提示</b>:\n"
            f"• 修改后需要重启机器人才能生效\n"
            f"• 如果一BOT管理多VPS，请为每个VPS设置不同前缀\n"
            f"• 避免使用特殊字符或空格",
            parse_mode="HTML"
        )
        return
    
    new_prefix = args[1].strip().lower()
    import re
    if not re.match(r'^[a-z0-9_]{3,20}$', new_prefix):
        await u.message.reply_text(
            "❌ <b>格式错误</b>\n\n"
            "前缀应为小写字母、数字、下划线，3-20字符\n"
            "例如: <code>vps1</code>, <code>server_a</code>, <code>mybot123</code>",
            parse_mode="HTML"
        )
        return
    
    # 更新配置
    conf['command_prefix'] = new_prefix
    from config import save_config
    save_config(conf)
    
    await u.message.reply_text(
        f"✅ <b>命令前缀已更新</b>\n\n"
        f"新前缀: <code>{new_prefix}</code>\n"
        f"新命令: <code>/{new_prefix}</code>\n\n"
        f"⚠️ <b>重要提示</b>:\n"
        f"• 需要重启机器人才能生效\n"
        f"• 如果一BOT管理多VPS，请为每个VPS设置不同前缀\n"
        f"• 旧命令 <code>/kk</code> 将失效\n\n"
        f"请使用 <code>/{new_prefix}</code> 菜单中的 '🔄 重启机器人' 按钮",
        parse_mode="HTML"
    )

# --- 📝 文本处理 ---
async def text_handler(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """处理用户发送的文本消息"""
    global STATE, SET_ACTION, WIZARD_STATE, CURRENT_UPLOAD_DIR, TEMP_API_NAME
    
    if u.effective_user.id not in ALLOWED_USER_IDS: 
        return
    
    text = u.message.text.strip()
    uid = u.effective_user.id
    
    # KK 指令处理
    if text.lower() == "kk":
        await kk_command(u, c)
        return

    # 设置项修改
    if STATE == "WAIT_SETTING":
        msg, (txt, kb) = settings_mod.update_setting(SET_ACTION, text)
        await u.message.reply_text(msg, parse_mode="HTML")
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # 设定上传目录
    elif STATE == "WAIT_UPLOAD_DIR":
        if os.path.isabs(text):
            os.makedirs(text, exist_ok=True)
            CURRENT_UPLOAD_DIR = text
            await u.message.reply_text(f"✅ <b>上传目录已更改为:</b>\n<code>{text}</code>", parse_mode="HTML")
            await start(u, c)
        else:
            await u.message.reply_text("❌ <b>请输入绝对路径!</b>(例如 <code>/root/myfiles</code>)", parse_mode="HTML")
        STATE = None
    
    # 备份路径添加
    elif STATE == "WAIT_BK_ADD":
        conf = load_config()
        if text not in conf['backup_paths']:
            conf['backup_paths'].append(text)
            save_config(conf)
        txt, kb = bk_mgr.get_backup_menu()
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # 自动备份时间设置
    elif STATE == "WAIT_BK_AUTO_TIME":
        conf = load_config()
        if text.lower() == "off":
            conf['auto_backup'] = {"mode": "off", "time": "03:00"}
            msg = "✅ 自动备份已禁用"
        elif re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$', text):
            conf['auto_backup'] = {"mode": "daily", "time": text}
            msg = f"✅ 自动备份时间已设定为: <code>{text}</code>"
        else:
            msg = "❌ 时间格式不正确! 请输入 <code>HH:MM</code> (例如 <code>23:55</code>)"
            await u.message.reply_text(msg, parse_mode="HTML")
            return
            
        save_config(conf)
        await u.message.reply_text(msg, parse_mode="HTML")
        txt, kb = bk_mgr.get_backup_menu()
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # Docker 向导 - 修改名称
    elif WIZARD_STATE == "WIZ_NAME":
        txt, kb = dk_mgr.update_wizard_val(uid, 'name', text)
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        WIZARD_STATE = None
    
    # Docker 向导 - 添加端口
    elif WIZARD_STATE == "WIZ_PORT":
        txt, kb = dk_mgr.update_wizard_val(uid, 'port', text)
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        WIZARD_STATE = None
    
    # Docker 向导 - 添加挂载
    elif WIZARD_STATE == "WIZ_VOL":
        txt, kb = dk_mgr.update_wizard_val(uid, 'vol', text)
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        WIZARD_STATE = None
    
    # Docker 向导 - 添加环境变量
    elif WIZARD_STATE == "WIZ_ENV":
        txt, kb = dk_mgr.update_wizard_val(uid, 'env', text)
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        WIZARD_STATE = None
    
    # 端口添加
    elif STATE == "WAIT_PORT_ADD":
        msg = net.add_port_rule(text)
        await u.message.reply_text(msg, parse_mode="HTML")
        txt, kb = net.build_port_menu()
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # 端口删除
    elif STATE == "WAIT_PORT_DEL":
        msg = net.del_port_rule(text)
        await u.message.reply_text(msg, parse_mode="HTML")
        txt, kb = net.build_port_menu()
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # 黑名单添加
    elif STATE == "WAIT_BAN_ADD":
        msg = net.add_ban_manual(text)
        await u.message.reply_text(msg, parse_mode="HTML")
        txt, kb = net.get_ban_list_view()
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # 黑名单删除
    elif STATE == "WAIT_BAN_DEL":
        msg = net.remove_ban_manual(text)
        await u.message.reply_text(msg, parse_mode="HTML")
        txt, kb = net.get_ban_list_view()
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None
    
    # 黑名单搜索
    elif STATE == "WAIT_BAN_SEARCH":
        txt, kb = net.get_ban_list_view(page=0, search_query=text)
        await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        STATE = None

    # SSH 端口修改 - 安全加固版
    elif STATE == "WAIT_SSH_PORT":
        if not validate_port(text):
            await u.message.reply_text("❌ <b>请输入有效的端口号!</b> (1-65535)", parse_mode="HTML")
            STATE = None
            return
        
        new_port = text
        await u.message.reply_text(
            f"⏳ <b>正在迁移 SSH 到端口 {new_port}...</b>\n"
            f"请稍候，这可能需要几秒钟。",
            parse_mode="HTML"
        )
        
        try:
            # 1. 备份 sshd_config
            conf_file = "/etc/ssh/sshd_config"
            backup_file = f"/etc/ssh/sshd_config.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            if os.path.exists(conf_file):
                shutil.copy2(conf_file, backup_file)
            
            # 2. 先放行新端口防火墙 (使用列表形式防止注入)
            safe_subprocess_run(
                ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", new_port, "-j", "ACCEPT"],
                check=True
            )
            
            # 3. 修改 sshd_config
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    lines = f.readlines()
                
                with open(conf_file, 'w') as f:
                    port_set = False
                    for line in lines:
                        if line.strip().startswith('Port '):
                            f.write(f"Port {new_port}\n")
                            port_set = True
                        else:
                            f.write(line)
                    if not port_set:
                        f.write(f"\nPort {new_port}\n")
            
            # 4. 重启 SSH 服务 (使用列表形式)
            safe_subprocess_run(["systemctl", "restart", "ssh"], check=True)
            
            await u.message.reply_text(
                f"✅ <b>SSH 端口已修改为:</b> <code>{new_port}</code>\n\n"
                f"💡 <b>温馨提示:</b>\n"
                f"请确保您的连接客户端已更新端口。\n"
                f"如果连接失败，请检查服务商的安全组设置。\n\n"
                f"📦 备份文件: <code>{backup_file}</code>",
                parse_mode="HTML"
            )
        except Exception as e:
            # 尝试恢复备份
            if os.path.exists(backup_file):
                shutil.copy2(backup_file, conf_file)
                safe_subprocess_run(["systemctl", "restart", "ssh"], check=True)
                await u.message.reply_text(
                    f"❌ <b>修改失败，已自动恢复:</b>\n<code>{sanitize_html(str(e))}</code>",
                    parse_mode="HTML"
                )
            else:
                await u.message.reply_text(
                    f"❌ <b>修改失败:</b>\n<code>{sanitize_html(str(e))}</code>",
                    parse_mode="HTML"
                )
        
        STATE = None
        await start(u, c)

    # Docker 命令执行 - 安全加固版
    elif STATE.startswith("WAIT_DK_EXEC_"):
        cid = STATE.replace("WAIT_DK_EXEC_", "")
        
        # 安全检查：验证容器ID格式
        if not re.match(r'^[a-f0-9]{12,64}$', cid):
            await u.message.reply_text("❌ <b>容器ID格式无效</b>", parse_mode="HTML")
            STATE = None
            return
        
        await u.message.reply_text(
            f"⏳ <b>正在执行:</b> <code>{sanitize_html(text)}</code>...",
            parse_mode="HTML"
        )
        
        try:
            # 使用列表形式执行命令，防止命令注入
            cmd = ["docker", "exec", cid] + text.split()
            result = safe_subprocess_run(cmd, timeout=15)
            
            output = result.stdout.decode('utf-8') if result.stdout else ""
            error = result.stderr.decode('utf-8') if result.stderr else ""
            
            if result.returncode == 0:
                await u.message.reply_text(
                    f"✅ <b>执行结果:</b>\n<code>{sanitize_html(output[:3500])}</code>",
                    parse_mode="HTML"
                )
            else:
                await u.message.reply_text(
                    f"❌ <b>执行出错:</b>\n<code>{sanitize_html(error[:500])}</code>",
                    parse_mode="HTML"
                )
        except Exception as e:
            await u.message.reply_text(
                f"❌ <b>执行异常:</b>\n<code>{sanitize_html(str(e))}</code>",
                parse_mode="HTML"
            )
        
        STATE = None
        await start(u, c)
    
    # IP 监控 - 手动设置 IP
    elif STATE == "WAIT_IP_SET":
        if validate_ip(text):
            ip_mon.update_last_known_ip(text)
            await u.message.reply_text(
                f"✅ <b>IP 已手动设置为:</b> <code>{text}</code>",
                parse_mode="HTML"
            )
            log_audit("USER", "手动设置IP", text)
            txt, kb = ip_mon.get_ip_monitor_menu()
            await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        else:
            await u.message.reply_text(
                "❌ <b>无效的 IP 地址格式</b>\n\n请输入有效的 IPv4 地址，例如: <code>1.2.3.4</code>",
                parse_mode="HTML"
            )
        STATE = None
    
    # API 模板添加 - 第1步：名称
    elif STATE == "WAIT_API_ADD_NAME":
        if text.strip() and len(text.strip()) <= 30:
            # 保存临时名称，进入下一步
            STATE = "WAIT_API_ADD_URL"
            TEMP_API_NAME = text.strip()
            await u.message.reply_text(
                f"✅ 模板名称: <code>{text.strip()}</code>\n\n"
                f"第 2 步: 请输入 API URL\n\n"
                f"<b>支持的格式:</b>\n"
                f"• <code>https://example.com/api.php?action=change_ip&token={'{token}'}</code>\n"
                f"• <code>http://10.1.1.1/changeip/changeip.aspx</code>\n"
                f"• <code>https://api.xxx/ipch/xxxxx</code>\n\n"
                f"<b>可用变量:</b>\n"
                f"• <code>{{service_id}}</code> - 服务ID\n"
                f"• <code>{{token}}</code> - Token\n"
                f"• <code>{{current_ip}}</code> - 当前IP",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="ip_api_list")]]),
                parse_mode="HTML"
            )
        else:
            await u.message.reply_text(
                "❌ <b>名称格式无效</b>\n\n请输入 1-30 个字符的名称",
                parse_mode="HTML"
            )
            STATE = None
    
    # API 模板添加 - 第2步：URL
    elif STATE == "WAIT_API_ADD_URL":
        is_valid, msg = ip_mon.validate_api_url(text)
        if is_valid:
            # 保存模板
            template_id = ip_mon.add_api_template(
                name=TEMP_API_NAME,
                url=text.strip()
            )
            await u.message.reply_text(
                f"✅ <b>API 模板已添加!</b>\n\n"
                f"名称: <code>{TEMP_API_NAME}</code>\n"
                f"URL: <code>{text[:50]}{'...' if len(text) > 50 else ''}</code>\n\n"
                f"💡 提示: 如果 URL 需要 token 等参数，请到「共享参数设置」中配置",
                parse_mode="HTML"
            )
            log_audit("USER", "添加API模板", f"{TEMP_API_NAME}: {text[:50]}")
            txt, kb = ip_mon.get_api_list_menu()
            await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        else:
            await u.message.reply_text(
                f"❌ <b>URL 验证失败:</b> {msg}\n\n请重新输入:",
                parse_mode="HTML"
            )
            return  # 保持状态，让用户重新输入
        STATE = None
    
    # 共享参数 - Service ID
    elif STATE == "WAIT_API_SID":
        if text.strip() and len(text.strip()) <= 50:
            conf = load_config()
            conf['api_service_id'] = text.strip()
            save_config(conf)
            await u.message.reply_text(
                "✅ <b>Service ID 已设置</b>",
                parse_mode="HTML"
            )
            log_audit("USER", "设置Service ID", "***")
            txt, kb = ip_mon.get_shared_settings_menu()
            await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        else:
            await u.message.reply_text(
                "❌ <b>Service ID 格式无效</b>",
                parse_mode="HTML"
            )
        STATE = None
    
    # 共享参数 - Token
    elif STATE == "WAIT_API_TOKEN":
        if text.strip() and len(text.strip()) <= 100:
            conf = load_config()
            conf['api_token'] = text.strip()
            save_config(conf)
            await u.message.reply_text(
                "✅ <b>Token 已设置</b>",
                parse_mode="HTML"
            )
            log_audit("USER", "设置Token", "***")
            txt, kb = ip_mon.get_shared_settings_menu()
            await u.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")
        else:
            await u.message.reply_text(
                "❌ <b>Token 格式无效</b>",
                parse_mode="HTML"
            )
        STATE = None

# --- 📘 按钮处理 (完整版) ---
async def btn_handler(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """处理所有按钮点击"""
    global STATE, SET_ACTION, WIZARD_STATE, CURRENT_UPLOAD_DIR
    
    q = u.callback_query
    d = q.data
    uid = u.effective_user.id
    
    try:
        await q.answer()
    except:
        pass

    # ==================== 流量审计 ====================
    if d == "sys_traffic_h":
        txt, kb = net.get_traffic_hourly()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "sys_traffic_d":
        txt, kb = net.get_traffic_history()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "sys_traffic_r":
        await q.answer("⏳...")
        txt, kb = net.get_traffic_realtime()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "sys_traffic_rank":
        txt, kb = net.get_traffic_ranking()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "sys_traffic_report_toggle":
        conf = load_config()
        curr = conf.get('traffic_daily_report', False)
        conf['traffic_daily_report'] = not curr
        save_config(conf)
        await q.answer(f"{'✅' if not curr else '❌'} 流量日报已{'开启' if not curr else '关闭'}")
        txt, kb = net.get_traffic_hourly()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # ==================== 基础路由 ====================
    elif d == "sys_report":
        txt, kb = sys_mod.get_system_report()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "sys_restart_bot":
        await q.answer("🔄 重启中...")
        os._exit(0)
    
    elif d == "sys_get_log":
        log_txt = get_audit_tail(50)
        await q.edit_message_text(
            f"📜 <b>审计日志 (最近50条)</b>\n<code>{log_txt}</code>", 
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="back")]]),
            parse_mode="HTML"
        )
    
    elif d == "back":
        await start(u, c)
    
    # ==================== IP 监控 ====================
    elif d == "ip_mon_menu":
        txt, kb = ip_mon.get_ip_monitor_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "ip_mon_toggle":
        conf = load_config()
        if 'ip_monitor' not in conf:
            conf['ip_monitor'] = {}
        curr = conf['ip_monitor'].get('enabled', False)
        conf['ip_monitor']['enabled'] = not curr
        save_config(conf)
        await q.answer(f"{'✅ 已启用' if not curr else '❌ 已禁用'} IP 监控")
        txt, kb = ip_mon.get_ip_monitor_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "ip_mon_check":
        await q.answer("🔍 检测中...")
        changed, old_ip, new_ip = ip_mon.check_ip_changed()
        if changed:
            txt = (f"🚨 <b>检测到 IP 变化!</b>\n\n"
                   f"📝 旧 IP: <code>{old_ip}</code>\n"
                   f"🆕 新 IP: <code>{new_ip}</code>\n\n"
                   f"已自动更新记录。")
            log_audit("USER", "IP变化检测", f"IP从 {old_ip} 变为 {new_ip}")
        else:
            txt = f"✅ IP 未变化\n\n当前 IP: <code>{new_ip}</code>"
        await q.answer(txt[:100])
        txt2, kb = ip_mon.get_ip_monitor_menu()
        await q.edit_message_text(
            f"{txt}\n\n━━━━━━━━━━━━━━━\n\n{txt2}",
            reply_markup=kb, parse_mode="HTML"
        )
    
    elif d == "ip_mon_set":
        STATE = "WAIT_IP_SET"
        await q.edit_message_text(
            "📝 <b>手动设置当前 IP</b>\n\n"
            "请输入当前的公网 IP 地址:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="ip_mon_menu")]]),
            parse_mode="HTML"
        )
    
    elif d == "ip_api_list":
        txt, kb = ip_mon.get_api_list_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "ip_api_add":
        STATE = "WAIT_API_ADD_NAME"
        await q.edit_message_text(
            "➕ <b>添加 API 模板</b>\n\n"
            "第 1 步: 请输入模板名称\n"
            "例如: <code>更换IP</code> 或 <code>查询状态</code>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="ip_api_list")]]),
            parse_mode="HTML"
        )
    
    elif d.startswith("ip_api_toggle_"):
        template_id = d.replace("ip_api_toggle_", "")
        ip_mon.toggle_api_template(template_id)
        txt, kb = ip_mon.get_api_list_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("ip_api_del_"):
        template_id = d.replace("ip_api_del_", "")
        # 确认删除
        template = ip_mon.get_api_template_by_id(template_id)
        name = template.get('name', '未知') if template else '未知'
        txt = f"⚠️ <b>确认删除模板?</b>\n\n模板: <code>{name}</code>"
        kb = [[InlineKeyboardButton("✅ 确认删除", callback_data=f"ip_api_del_yes_{template_id}")],
              [InlineKeyboardButton("❌ 取消", callback_data="ip_api_list")]]
        await q.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    
    elif d.startswith("ip_api_del_yes_"):
        template_id = d.replace("ip_api_del_yes_", "")
        ip_mon.remove_api_template(template_id)
        await q.answer("🗑️ 已删除")
        txt, kb = ip_mon.get_api_list_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("ip_api_run_"):
        template_id = d.replace("ip_api_run_", "")
        template = ip_mon.get_api_template_by_id(template_id)
        if template:
            name = template.get('name', '未知')
            # 确认执行
            txt = (f"⚠️ <b>确认执行?</b>\n\n"
                   f"模板: <code>{name}</code>\n"
                   f"URL: <code>{template.get('url', '')[:50]}...</code>")
            kb = [[InlineKeyboardButton("✅ 确认执行", callback_data=f"ip_api_run_yes_{template_id}")],
                  [InlineKeyboardButton("❌ 取消", callback_data="ip_api_list")]]
            await q.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    
    elif d.startswith("ip_api_run_yes_"):
        template_id = d.replace("ip_api_run_yes_", "")
        await q.answer("⏳ 执行中...")
        success, data = ip_mon.call_api_template(template_id, ip_mon.get_shared_variables())
        if success:
            txt = f"✅ <b>API 调用成功</b>\n\n{ip_mon.format_api_response(data)}"
        else:
            txt = f"❌ <b>API 调用失败</b>\n\n{sanitize_html(str(data))}"
        kb = [[InlineKeyboardButton("🔄 重新执行", callback_data=f"ip_api_run_{template_id}")],
              [InlineKeyboardButton("🔙 返回", callback_data="ip_api_list")]]
        await q.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    
    elif d == "ip_api_shared":
        txt, kb = ip_mon.get_shared_settings_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "ip_share_set_sid":
        STATE = "WAIT_API_SID"
        await q.edit_message_text(
            "🔑 <b>设置 Service ID</b>\n\n"
            "请输入您的 Service ID:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="ip_api_shared")]]),
            parse_mode="HTML"
        )
    
    elif d == "ip_share_set_token":
        STATE = "WAIT_API_TOKEN"
        await q.edit_message_text(
            "🔐 <b>设置 Token</b>\n\n"
            "请输入您的 API Token:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="ip_api_shared")]]),
            parse_mode="HTML"
        )
    
    # ==================== 设置中心 ====================
    elif d == "sent_lab":
        txt, kb = settings_mod.get_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "set_ssh_security":
        txt, kb = settings_mod.get_ssh_security_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        
    elif d == "set_ssh_port_warn":
        txt = ("⚠️ <b>高风险操作确认</b>\n"
               "━━━━━━━━━━━━━━━\n"
               "修改 SSH 端口可能会导致您无法连接服务器，请务必确认以下事项：\n\n"
               "1. 您是否有<b>其他连接方式</b>（如 VNC 控制台）以防万一？\n"
               "2. 如果您的 VPS 有<b>外部防火墙/安全组</b>（如搬瓦工面板、阿里云），您必须先在面板放行新端口。\n"
               "3. 修改后，机器人会自动帮您放行系统内部防火墙并重启 SSH。\n\n"
               "确定要继续吗？")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ 我已知晓风险，继续", callback_data="set_ssh_port_input")],
            [InlineKeyboardButton("❌ 取消返回", callback_data="set_ssh_security")]
        ])
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d == "set_ssh_port_input":
        STATE = "WAIT_SSH_PORT"
        await q.edit_message_text("⌨️ <b>请输入新的 SSH 端口号:</b>\n(建议范围: 1024-65535)", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="set_ssh_security")]]), parse_mode="HTML")

    elif d == "set_ssh_dur_list":
        txt, kb = settings_mod.get_ssh_duration_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        
    elif d.startswith("set_ssh_dur_"):
        duration = d.replace("set_ssh_dur_", "")
        conf = load_config()
        conf['ban_duration'] = duration
        save_config(conf)
        await q.answer(f"⏳ 封禁时长已设为: {duration}")
        txt, kb = settings_mod.get_ssh_security_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        
    elif d.startswith("ssh_fail_ip_"):
        ip = d.replace("ssh_fail_ip_", "")
        txt, kb = settings_mod.get_ssh_fail_detail(ip)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("set_"):
        STATE = "WAIT_SETTING"
        SET_ACTION = d
        prompt = settings_mod.get_prompt_text(d)
        await q.edit_message_text(
            prompt, 
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="sent_lab")]]), 
            parse_mode="HTML"
        )
    
    # ==================== 备份管理 ====================
    elif d == "bk_menu":
        txt, kb = bk_mgr.get_backup_menu()
        # 加入上传目录管理按钮
        kb_list = list(kb.inline_keyboard)
        kb_list.insert(2, [InlineKeyboardButton("📥 设定上传目录", callback_data="tool_set_upload")])
        await q.edit_message_text(f"{txt}\n\n📍 当前上传指向: <code>{CURRENT_UPLOAD_DIR}</code>", reply_markup=InlineKeyboardMarkup(kb_list), parse_mode="HTML")

    elif d == "tool_set_upload":
        STATE = "WAIT_UPLOAD_DIR"
        await q.edit_message_text("⌨️ <b>请输入新的上传绝对路径:</b>\n(例如 <code>/home/vboxuser/下载</code>)", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="bk_menu")]]), parse_mode="HTML")

    elif d == "tool_upload_start":
        STATE = "WAIT_UPLOAD_FILE"
        await q.edit_message_text(f"📤 <b>请现在发送文件到此对话框</b>\n\n文件将会自动存入:\n<code>{CURRENT_UPLOAD_DIR}</code>", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 取消", callback_data="bk_menu")]]), parse_mode="HTML")
    
    elif d == "bk_history":
        txt, kb = bk_mgr.build_history_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("bk_send_"):
        filename = d.replace("bk_send_", "")
        filepath = f"/tmp/{filename}"
        if os.path.exists(filepath):
            await q.answer("📤 发送中...")
            with open(filepath, 'rb') as f:
                await q.message.reply_document(document=f, caption=f"📦 历史备份: <code>{filename}</code>")
        else:
            await q.answer("❌ 文件已丢失", show_alert=True)
    
    elif d == "bk_do":
        await q.answer("📦 备份中...")
        await q.edit_message_text("⏳ <b>正在打包备份...</b>\n请稍候...", parse_mode="HTML")
        file_path, msg = bk_mgr.run_backup_task()
        
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    await q.message.reply_document(
                        document=f,
                        caption=msg,
                        parse_mode="HTML"
                    )
                os.remove(file_path)
                txt, kb = bk_mgr.get_backup_menu()
                await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
            except Exception as e:
                await q.edit_message_text(f"❌ 文件发送失败: {str(e)}", parse_mode="HTML")
        else:
            await q.edit_message_text(msg, parse_mode="HTML")
    
    elif d == "bk_add":
        STATE = "WAIT_BK_ADD"
        await q.edit_message_text("请输入要备份的路径 (如 <code>/etc/wireguard</code>):", parse_mode="HTML")

    elif d == "bk_auto_set":
        STATE = "WAIT_BK_AUTO_TIME"
        await q.edit_message_text("⌨️ <b>请输入每天自动备份的时间:</b>\n(24小时制, 例如 <code>23:55</code>, 输入 <code>off</code> 禁用)", parse_mode="HTML")

    elif d.startswith("bk_del_path_"):
        idx = int(d.split('_')[3])
        conf = load_config()
        paths = conf.get('backup_paths', [])
        if 0 <= idx < len(paths):
            removed = paths.pop(idx)
            save_config(conf)
            await q.answer(f"🗑️ 已移除: {removed}")
        txt, kb = bk_mgr.get_backup_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # ==================== 工具箱 ====================
    elif d == "tool_box":
        kb = [
            [InlineKeyboardButton("📌 监听", callback_data="tool_listen"), 
             InlineKeyboardButton("🕵️ 扫鬼", callback_data="tool_ghost")],
            [InlineKeyboardButton("🧹 清理", callback_data="tool_clean"), 
             InlineKeyboardButton("🚫 黑名单", callback_data="tool_ban")],
            [InlineKeyboardButton("🔙", callback_data="back")]
        ]
        await q.edit_message_text("🧰 工具箱", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    
    elif d == "tool_listen":
        txt, kb = net.get_listen_text()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 容器健康检查
    elif d == "health_check":
        await q.answer("🥼 检查中...")
        txt, kb = health_mod.get_health_report_view()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("health_page_"):
        page = int(d.split('_')[2])
        txt, kb = health_mod.get_health_report_view(page)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("health_detail_"):
        cid = d.split('_')[2]
        txt, kb = health_mod.get_container_detail_health(cid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 一键故障诊断
    elif d == "sys_diagnose":
        await q.answer("🔧 诊断中...")
        txt, kb = sys_mod.get_auto_diagnosis()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 扫鬼行动
    elif d == "tool_ghost":
        txt, kb = net.get_ghost_process_view()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("ghost_detail_"):
        parts = d.split('_')
        proc = parts[2]
        page = int(parts[3])
        txt, kb = net.get_ghost_detail_view(proc, page)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("ghost_ban_ip_"):
        parts = d.split('_')
        # ghost_ban_ip_进程名_页码_IP
        proc = parts[3]
        page = int(parts[4])
        ip = parts[5]
        msg = net.add_ban_manual(ip)
        await q.answer(f"🚫 {ip} 已送入黑名单")
        txt, kb = net.get_ghost_detail_view(proc, page)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("ghost_proc_"):
        parts = d.split('_')
        proc = parts[2]
        page = int(parts[3])
        txt, kb = net.get_ghost_detail_view(proc, page)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("ghost_opt_"):
        parts = d.split('_')
        ip = parts[2]
        proc = parts[3]
        page = int(parts[4])
        txt, kb = net.get_ban_option_menu(ip, proc, page)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("ghost_ban_"):
        parts = d.split('_')
        target = parts[2]
        ban_type = parts[3]
        proc = parts[4]
        page = int(parts[5])
        msg = net.execute_tactical_ban(target, ban_type)
        await q.answer(msg[:100])
        txt, kb = net.get_ghost_detail_view(proc, page)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("ghost_quick_ban_"):
        ip = d.replace("ghost_quick_ban_", "")
        msg = net.add_ban_manual(ip) # 使用现有的添加黑名单函数，确保同步记录到日志和iptables
        await q.answer(f"🚫 {ip} 已送入黑名单")
        txt, kb = net.get_ghost_process_view()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 清理功能
    elif d == "tool_clean":
        txt, kb = sys_mod.get_clean_menu(uid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("clean_sw_"):
        txt, kb = sys_mod.toggle_clean_option(uid, d.split("_")[2])
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "clean_run":
        await q.answer("🧹 清理中...")
        txt, kb = sys_mod.run_smart_clean(uid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 黑名单
    elif d == "tool_ban":
        txt, kb = net.get_ban_list_view()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("net_bl_page_"):
        parts = d.split('_')
        page = int(parts[3])
        search = parts[4] if len(parts) > 4 else None
        txt, kb = net.get_ban_list_view(page, search)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "net_op_add":
        STATE = "WAIT_BAN_ADD"
        await q.edit_message_text("请输入要封禁的 IP 或 CIDR (如 <code>1.2.3.4</code> 或 <code>1.2.3.0/24</code>):", parse_mode="HTML")
    
    elif d == "net_op_del":
        STATE = "WAIT_BAN_DEL"
        await q.edit_message_text("请输入要解封的 IP 或 CIDR:", parse_mode="HTML")
    
    elif d == "net_op_search":
        STATE = "WAIT_BAN_SEARCH"
        await q.edit_message_text("🔍 请输入搜索关键词 (IP片段):", parse_mode="HTML")
    
    elif d == "net_op_reset_ask":
        kb = [
            [InlineKeyboardButton("✅ 确认清空", callback_data="net_op_reset_yes"), 
             InlineKeyboardButton("❌ 取消", callback_data="tool_ban")]
        ]
        await q.edit_message_text("⚠️ <b>危险操作</b>\n\n确定要清空所有黑名单规则吗?", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    
    elif d == "net_op_reset_yes":
        msg = net.reset_all_bans()
        await q.answer(msg[:100])
        txt, kb = net.get_ban_list_view()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # ==================== 端口控制 ====================
    elif d == "net_ports":
        txt, kb = net.build_port_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("net_ssh_"):
        port = d.split('_')[2]
        msg = net.toggle_ssh(port)
        await q.answer(msg)
        txt, kb = net.build_port_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "net_ping":
        msg = net.toggle_ping()
        await q.answer(msg)
        txt, kb = net.build_port_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("net_biz_"):
        port = d.split('_')[2]
        msg = net.toggle_port(port)
        await q.answer(msg)
        txt, kb = net.build_port_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "net_add":
        STATE = "WAIT_PORT_ADD"
        await q.edit_message_text("请输入端口和描述 (格式: <code>8080 Web服务</code>):", parse_mode="HTML")
    
    elif d == "net_del":
        STATE = "WAIT_PORT_DEL"
        await q.edit_message_text("请输入要删除的端口号:", parse_mode="HTML")
    
    elif d == "net_reset":
        msg = net.set_whitelist_mode(True)
        await q.answer(msg)
        txt, kb = net.build_port_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "net_rescue":
        msg = net.set_whitelist_mode(False)
        await q.answer(msg)
        txt, kb = net.build_port_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # ==================== 🏠 内网访问管理 (新增核心) ====================
    elif d == "net_lan_manage":
        # 进入内网管理,自动初始化默认规则
        await q.answer("🔍 检测中...")
        net.init_default_networks()
        txt, kb = net.get_network_manage_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "net_lan_refresh":
        # 刷新检测
        await q.answer("🔄 重新检测...")
        net.init_default_networks()
        txt, kb = net.get_network_manage_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "net_lan_add":
        # 手动添加网段 (暂未实现)
        await q.answer("⚠️ 此功能正在开发中,请先使用自动检测")
    
    elif d.startswith("net_lan_"):
        # 切换网段状态
        # 格式: net_lan_192.168.1.0_24
        try:
            network_parts = d.replace("net_lan_", "").split("_")
            if len(network_parts) >= 2:
                # 重建 CIDR 格式: 192.168.1.0/24
                # 处理点号分隔的IP部分
                ip_parts = []
                cidr_part = network_parts[-1]  # 最后一个是CIDR掩码
                
                # 重建IP地址
                for i, part in enumerate(network_parts[:-1]):
                    ip_parts.append(part)
                    # 每4个部分加一个点 (IPv4)
                    if (i + 1) % 1 == 0 and i < len(network_parts) - 2:
                        pass  # 已经通过split分割了
                
                # 拼接完整网段
                network = ".".join(ip_parts) + "/" + cidr_part
                
                msg = net.toggle_network_access(network)
                await q.answer(msg[:100])
                txt, kb = net.get_network_manage_menu()
                await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        except Exception as e:
            await q.answer(f"❌ 操作失败: {str(e)}")
    
    # ==================== Docker 管理 ====================
    elif d == "dk_m":
        txt, kb = dk_mgr.build_main_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_op_prune":
        await q.answer("🧹 清理中...")
        msg = dk_mgr.prune_docker_resources()
        await q.edit_message_text(msg, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data="dk_m")]]), parse_mode="HTML")
    
    elif d == "dk_list_cons":
        txt, kb = dk_mgr.build_container_list()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_list_stacks":
        txt, kb = dk_mgr.build_stack_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_res_imgs":
        txt, kb = dk_mgr.build_image_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_store":
        txt, kb = dk_mgr.build_app_store_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        
    elif d.startswith("dk_store_ask_"):
        app_key = d.replace("dk_store_ask_", "")
        txt, kb = dk_mgr.build_app_install_confirm(app_key)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("dk_store_do_"):
        app_key = d.replace("dk_store_do_", "")
        await q.answer("🚀 正在初始化安装向导...")
        # 增加一个中间过渡状态，提升交互感
        await q.edit_message_text("⌛ <b>正在为您准备安装环境...</b>\n请稍候...", parse_mode="HTML")
        
        if dk_mgr.install_app_template(uid, app_key):
            txt, kb = dk_mgr.get_wizard_menu(uid)
            await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        else:
            await q.answer("❌ 模板不存在", show_alert=True)
            
    elif d == "dk_events":
        events = dk_mgr.get_docker_events()
        await q.edit_message_text(f"📝 <b>Docker 事件流</b>\n<code>{events}</code>", parse_mode="HTML")
    
    # 容器详情
    elif d.startswith("dk_view_"):
        cid = d.split('_')[2]
        txt, kb = dk_mgr.build_container_dashboard(cid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("dk_log_v_"):
        cid = d.split('_')[3]
        txt, kb = dk_mgr.build_logs_preview(cid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("dk_op_exec_ask_"):
        cid = d.replace("dk_op_exec_ask_", "")
        STATE = f"WAIT_DK_EXEC_{cid}"
        await q.edit_message_text("💻 <b>请输入要在容器内执行的命令:</b>\n(例如 <code>ls -la</code>, <code>df -h</code>, <code>python --version</code>)", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 取消", callback_data=f"dk_view_{cid}")]]), parse_mode="HTML")
    
    # 容器操作
    elif d.startswith("dk_op_"):
        parts = d.split('_')
        action = parts[2]
        target = parts[3]
        await q.answer("⏳ 执行中...")
        success, msg = dk_mgr.docker_action(action, target)
        await q.answer(f"{'✅' if success else '❌'} {msg}")
        txt, kb = dk_mgr.build_container_list()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 镜像详情
    elif d.startswith("dk_img_v_"):
        iid = d.split('_')[3]
        txt, kb = dk_mgr.build_image_dashboard(iid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("dk_img_upd_"):
        tag = '_'.join(d.split('_')[3:])
        await q.answer("🔄 更新中...")
        msg = dk_mgr.update_image(tag)
        await q.answer(msg[:100])
        txt, kb = dk_mgr.build_image_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("dk_img_hist_"):
        iid = d.split('_')[3]
        layers = dk_mgr.get_image_layers(iid)
        await q.edit_message_text(f"🍰 <b>镜像层信息</b>\n{layers}", parse_mode="HTML")
    
    # 向导流程
    elif d.startswith("dk_wiz_new_"):
        iid = d.split('_')[3]
        if dk_mgr.init_wizard(uid, iid):
            txt, kb = dk_mgr.get_wizard_menu(uid)
            await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
        else:
            await q.answer("❌ 镜像不存在")
    
    elif d == "dk_wiz_back":
        txt, kb = dk_mgr.get_wizard_menu(uid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_wiz_set_name":
        WIZARD_STATE = "WIZ_NAME"
        await q.edit_message_text("请输入容器名称:", parse_mode="HTML")
    
    elif d == "dk_wiz_set_port":
        WIZARD_STATE = "WIZ_PORT"
        await q.edit_message_text("请输入端口映射 (格式: <code>8080:80</code>):", parse_mode="HTML")
    
    elif d == "dk_wiz_set_vol":
        WIZARD_STATE = "WIZ_VOL"
        await q.edit_message_text("请输入挂载路径 (格式: <code>/host/path:/container/path</code>):", parse_mode="HTML")
    
    elif d == "dk_wiz_set_env":
        WIZARD_STATE = "WIZ_ENV"
        await q.edit_message_text("请输入环境变量 (格式: <code>KEY=VALUE</code>):", parse_mode="HTML")
    
    elif d == "dk_wiz_net":
        txt, kb = dk_mgr.get_net_select_menu(uid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("dk_wiz_val_net_"):
        net_name = d.split('_')[4]
        txt, kb = dk_mgr.update_wizard_val(uid, 'net', net_name)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_wiz_adv":
        txt, kb = dk_mgr.get_advanced_menu(uid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_wiz_toggle_priv":
        txt, kb = dk_mgr.update_wizard_val(uid, 'privileged', None)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d == "dk_wiz_commit":
        await q.answer("🚀 正在创建容器...")
        await q.edit_message_text("⏳ <b>正在拉取镜像并部署容器...</b>\n這可能需要幾十秒，請稍候...", parse_mode="HTML")
        msg = dk_mgr.commit_wizard(uid)
        await q.edit_message_text(msg, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回列表", callback_data="dk_list_cons")]]), parse_mode="HTML")
    
    # Stack 操作
    elif d.startswith("dk_stack_opt_"):
        name = d.split('_')[3]
        txt, kb = dk_mgr.build_stack_dashboard(name)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("dk_sop_"):
        parts = d.split('_')
        action = f"stack_{parts[2]}"
        name = parts[3]
        await q.answer("⏳ 执行中...")
        success, msg = dk_mgr.docker_action(action, name)
        await q.answer(f"{'✅' if success else '❌'} {msg}")
        txt, kb = dk_mgr.build_stack_menu()
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    # 资源限制
    elif d.startswith("dk_lim_menu_"):
        cid = d.split('_')[3]
        txt, kb = dk_mgr.build_limit_menu(cid)
        await q.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    
    elif d.startswith("dk_set_lim_"):
        parts = d.split('_')
        cid = parts[3]
        limit = parts[4]
        await q.answer("⏳ 设置中...")
        success, msg = dk_mgr.docker_action("update_mem", cid, limit)
        txt, kb = dk_mgr.build_limit_menu(cid)
        try:
            await q.edit_message_text(f"{txt}\n\n{'✅ 设置成功' if success else '❌ ' + msg}", reply_markup=kb, parse_mode="HTML")
        except: pass

async def traffic_monitor(app: Application):
    """系统综合监控 (流量 + 资源极限)"""
    while True:
        try:
            await asyncio.sleep(60)
            conf = load_config()
            used = sys_mod.get_traffic_stats('day')
            limit = conf.get('daily_warn_gb', 50)
            if used > limit:
                today_str = datetime.now().strftime("%Y-%m-%d")
                if conf.get('last_daily_warn_date') != today_str:
                    txt = f"🚨 <b>流量预警</b>\n📉 今日已用: <code>{used:.2f} GB</code>\n🛑 设定阈值: <code>{limit} GB</code>"
                    for uid in ALLOWED_USER_IDS:
                        await app.bot.send_message(chat_id=uid, text=txt, parse_mode="HTML")
                    conf['last_daily_warn_date'] = today_str
                    save_config(conf)
            alerts = sys_mod.check_system_limits()
            if alerts:
                for uid in ALLOWED_USER_IDS:
                    await app.bot.send_message(chat_id=uid, text="🛑 <b>系统极限报警</b>\n" + "\n".join(alerts), parse_mode="HTML")
        except Exception as e:
            logging.error(f"监控异常: {e}")
            await asyncio.sleep(60)

async def ssh_monitor(app: Application):
    """SSH 登录实时监控"""
    log_file = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
    if not os.path.exists(log_file): return
    try:
        proc = await asyncio.create_subprocess_exec("tail", "-n", "0", "-f", log_file, stdout=asyncio.subprocess.PIPE)
        while True:
            line = await proc.stdout.readline()
            if not line: break
            line_str = line.decode().strip()
            if "Accepted password" in line_str or "Accepted publickey" in line_str:
                parts = line_str.split()
                user = parts[parts.index("for") + 1]
                ip = parts[parts.index("from") + 1]
                txt = f"🕵️ <b>SSH 安全提醒</b>\n━━━━━━━━━━━━━━━\n👤 用户: <code>{user}</code>\n🌐 来源: <code>{ip}</code>\n⏰ 时间: <code>{datetime.now().strftime('%H:%M:%S')}</code>"
                for uid in ALLOWED_USER_IDS:
                    await app.bot.send_message(chat_id=uid, text=txt, parse_mode="HTML")
    except Exception as e:
        logging.error(f"SSH 监控异常: {e}")

async def backup_scheduler(app: Application):
    """定时任务中心"""
    while True:
        try:
            conf = load_config(); now = datetime.now(); now_hm = now.strftime("%H:%M")
            auto = conf.get("auto_backup", {})
            if auto.get("mode") != "off" and now_hm == auto.get("time", "03:00"):
                today_str = now.strftime("%Y-%m-%d")
                if auto.get("last_run") != today_str:
                    file_path, msg = bk_mgr.run_backup_task(is_auto=True)
                    if file_path:
                        for uid in ALLOWED_USER_IDS:
                            with open(file_path, 'rb') as f:
                                await app.bot.send_document(chat_id=uid, document=f, caption=f"⏰ <b>自动备份汇报</b>\n{msg}", parse_mode="HTML")
                        os.remove(file_path)
                    auto['last_run'] = today_str; conf['auto_backup'] = auto; save_config(conf)
            if now_hm in conf.get("daily_report_times", ["08:00", "20:00"]):
                report_key = f"last_report_{now_hm.replace(':','')}"
                if conf.get(report_key) != now.strftime("%Y-%m-%d"):
                    txt, kb = sys_mod.get_system_report()
                    prefix = "🌅 <b>系统简报</b>" if now.hour < 12 else "🌃 <b>运行总结</b>"
                    for uid in ALLOWED_USER_IDS:
                        await app.bot.send_message(chat_id=uid, text=f"{prefix}\n\n{txt}", parse_mode="HTML")
                    conf[report_key] = now.strftime("%Y-%m-%d"); save_config(conf)
            await asyncio.sleep(60)
        except Exception as e:
            logging.error(f"调度异常: {e}"); await asyncio.sleep(60)

async def traffic_daily_push(app: Application):
    """每日流量日报推送 (23:55)"""
    while True:
        try:
            now = datetime.now()
            if now.strftime("%H:%M") == "23:55":
                conf = load_config()
                if conf.get('traffic_daily_report'):
                    today_str = now.strftime("%Y-%m-%d")
                    if conf.get('last_traffic_report_date') != today_str:
                        txt = net.get_daily_traffic_report()
                        for uid in ALLOWED_USER_IDS:
                            await app.bot.send_message(chat_id=uid, text=txt, parse_mode="HTML")
                        conf['last_traffic_report_date'] = today_str
                        save_config(conf)
            await asyncio.sleep(60)
        except Exception as e:
            logging.error(f"流量日报推送异常: {e}")
            await asyncio.sleep(60)

async def ip_change_monitor(app: Application):
    """IP 变化监控任务"""
    while True:
        try:
            conf = load_config()
            ip_monitor = conf.get('ip_monitor', {})
            
            if ip_monitor.get('enabled', False):
                interval = ip_monitor.get('check_interval_minutes', 5)
                
                changed, old_ip, new_ip = ip_mon.check_ip_changed()
                
                if changed and old_ip and new_ip:
                    # IP 发生变化，发送通知
                    txt = (
                        f"🚨 <b>检测到 IP 变化!</b>\n"
                        f"━━━━━━━━━━━━━━━\n\n"
                        f"📝 旧 IP: <code>{old_ip}</code>\n"
                        f"🆕 新 IP: <code>{new_ip}</code>\n\n"
                        f"⏰ 时间: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
                    )
                    
                    for uid in ALLOWED_USER_IDS:
                        try:
                            await app.bot.send_message(chat_id=uid, text=txt, parse_mode="HTML")
                        except Exception as e:
                            logging.error(f"发送 IP 变化通知失败: {e}")
                    
                    log_audit("SYSTEM", "IP变化检测", f"IP从 {old_ip} 变为 {new_ip}")
                
                await asyncio.sleep(interval * 60)
            else:
                # 未启用监控，每分钟检查一次配置
                await asyncio.sleep(60)
                
        except Exception as e:
            logging.error(f"IP 监控异常: {e}")
            await asyncio.sleep(60)

async def post_init(application: Application) -> None:
    asyncio.create_task(docker_sentinel(application))
    asyncio.create_task(traffic_monitor(application))
    asyncio.create_task(backup_scheduler(application))
    asyncio.create_task(ssh_monitor(application))
    asyncio.create_task(traffic_daily_push(application))
    asyncio.create_task(ip_change_monitor(application))

if __name__ == "__main__":
    net.init_default_networks()
    app = Application.builder().token(TOKEN).post_init(post_init).build()
    
    # 读取配置获取命令前缀
    from config import load_config
    conf = load_config()
    command_prefix = conf.get('command_prefix', 'kk')
    
    # 注册命令
    app.add_handler(CommandHandler("b", start))  # 保持 /b 不变以向后兼容
    app.add_handler(CommandHandler(command_prefix, kk_command))  # 使用配置的前缀
    app.add_handler(CommandHandler("settoken", settoken_command))
    app.add_handler(CommandHandler("setadminid", setadminid_command))
    app.add_handler(CommandHandler("setprefix", setprefix_command))
    
    # 如果前缀不是默认的 'kk'，也注册 /kk 作为别名以保持兼容性
    if command_prefix != "kk":
        app.add_handler(CommandHandler("kk", kk_command))
        print(f"⚠️  注意: 命令前缀已设置为 '{command_prefix}'，但 /kk 仍可用作别名")
    
    app.add_handler(CallbackQueryHandler(btn_handler))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), text_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
    
    print(f"✅ VPS Bot V6.3-X 启动成功")
    print(f"📝 控制台命令: /{command_prefix} (原 /kk)")
    app.run_polling()
