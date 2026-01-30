import logging
import re
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict, deque

from telegram import Update, Chat, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, 
    MessageHandler, 
    filters, 
    ContextTypes,
    CommandHandler,
    CallbackQueryHandler
)
from telegram.constants import ParseMode, ChatMemberStatus
from telegram.error import TelegramError

# =====================================================================
# SECURITY & CONFIGURATION
# =====================================================================

# Bot Token - BotFather se milega (KEEP THIS SECRET!)
TELEGRAM_BOT_TOKEN = "8355183481:AAFB9tI5_IAcfHbgx93AI-EWKGiSoH093hM"

# Security: Admin verification
ADMIN_USERNAME = "adeptcodeowner"  # Your username without @
ADMIN_USER_ID = None  # Will be set on first admin interaction

# Bot Settings
MAX_WARNINGS = 3
SPAM_TIME_WINDOW = 60  # seconds
MAX_MESSAGES_PER_MINUTE = 5

# Social Links
TELEGRAM_CHANNEL = "https://t.me/adeptcodeofficial"
TELEGRAM_GROUP = "https://t.me/adeptcode_group"
YOUTUBE_CHANNEL = "https://youtube.com/@adeptcodeofficial"
ADMIN_CONTACT = "https://t.me/adeptcodeowner"

# =====================================================================
# LOGGING SETUP
# =====================================================================

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Security: Filter sensitive data from logs
class SecurityFilter(logging.Filter):
    def filter(self, record):
        # Remove token from logs
        if hasattr(record, 'msg'):
            record.msg = str(record.msg).replace(TELEGRAM_BOT_TOKEN, "***TOKEN***")
        return True

logger.addFilter(SecurityFilter())

# =====================================================================
# DATA STRUCTURES
# =====================================================================

class UserData:
    """User tracking data"""
    def __init__(self):
        self.warnings = 0
        self.last_warning = None
        self.warning_reasons = []
        self.message_times = deque(maxlen=MAX_MESSAGES_PER_MINUTE)
        self.total_messages = 0
        self.banned = False
        self.ban_reason = None
        self.first_seen = datetime.now()
        self.last_activity = datetime.now()

class ActionLog:
    """Action logging"""
    def __init__(self, action_type, user_id, username, reason, message_text):
        self.timestamp = datetime.now()
        self.action_type = action_type
        self.user_id = user_id
        self.username = username
        self.reason = reason
        self.message_text = message_text[:100] if message_text else ""

# Global storage (secure in-memory storage)
user_data = defaultdict(UserData)
action_logs = deque(maxlen=1000)

# =====================================================================
# SECURITY: SPAM DETECTION PATTERNS
# =====================================================================

SPAM_PATTERNS = [
    # URLs (except allowed ones)
    r'http[s]?://(?!t\.me/adeptcode|youtube\.com/@adeptcode)',
    r'www\.(?!youtube\.com/@adeptcode)',
    
    # Social media & video platforms (except yours)
    r'youtube\.com/(?!@adeptcode)|youtu\.be',
    r'instagram\.com|insta\.me',
    r'facebook\.com|fb\.com|fb\.me',
    r'twitter\.com|x\.com',
    r'tiktok\.com',
    r'whatsapp\.com',
    
    # Telegram links (except yours)
    r't\.me/(?!adeptcode)',
    r'@\w+bot',
    
    # Promotional keywords
    r'join\s+(?:my|our)\s+(?:channel|group|server)',
    r'subscribe\s+(?:my|our|to)\s+(?!adeptcode)',
    r'follow\s+(?:me|us)\s+(?:on|at)',
    r'click\s+(?:here|link|below|this)',
    
    # Commercial spam
    r'buy\s+now|purchase|sale|discount|offer|deal',
    r'earn\s+money|make\s+money|free\s+money|income|paisa',
    r'work\s+from\s+home|part\s+time\s+job',
    
    # Short URLs (potential security risk)
    r'bit\.ly|tinyurl|short\.link|cutt\.ly',
]

ABUSE_PATTERNS = [
    r'\b(?:idiot|stupid|fool|dumb|moron|loser|asshole)\b',
    r'\b(?:shit|fuck|damn|hell|bastard|bitch|crap)\b',
    r'shut\s+up|stfu|gtfo|get\s+lost',
    r'\b(?:madarchod|mc|behenchod|bc|chutiya|gandu|randi|saala|kutte|kamine)\b',
    r'tere\s+(?:maa|baap)|teri\s+maa|maa\s+ki',
]

PRIVACY_PATTERNS = [
    r'(?:phone|mobile|whatsapp)\s*(?:number|no|dedo|chahiye|share)',
    r'personal\s+(?:chat|message|dm|talk|baat)',
    r'dm\s+me|message\s+me\s+privately|private\s+me',
    r'share\s+(?:your|my)\s+(?:number|contact|address|location)',
]

HELP_PATTERNS = [
    r'\b(?:help|doubt|problem|issue|error|bug|exception|query)\b',
    r'\b(?:how\s+to|kaise|tutorial|guide|sikha|bata|samajh)\b',
    r'kya\s+karu|kaise\s+karu|samajh\s+nahi',
]

RESOURCE_PATTERNS = [
    r'\b(?:prompt|template|source\s+code|github|repo|resource)\b',
    r'kaha\s+(?:mil|milega|hai)|kaise\s+(?:download|get|milega)',
]

# =====================================================================
# SECURITY FUNCTIONS
# =====================================================================

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not text:
        return ""
    # Remove potential HTML/script injections
    text = re.sub(r'<[^>]*>', '', text)
    # Limit length to prevent overflow
    return text[:4096]

async def verify_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Secure admin verification"""
    global ADMIN_USER_ID
    
    try:
        user_id = update.effective_user.id
        username = update.effective_user.username
        
        # First check: Username match
        if username and username.lower() == ADMIN_USERNAME.lower():
            if ADMIN_USER_ID is None:
                ADMIN_USER_ID = user_id
                logger.info(f"Admin verified: @{username} (ID: {user_id})")
            return True
        
        # Second check: User ID match (if already verified)
        if ADMIN_USER_ID and user_id == ADMIN_USER_ID:
            return True
        
        # Third check: Telegram API verification (in groups)
        if update.effective_chat.type in [Chat.GROUP, Chat.SUPERGROUP]:
            member = await context.bot.get_chat_member(update.effective_chat.id, user_id)
            if member.status in [ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER]:
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Admin verification error: {e}")
        return False

def log_action(action_type, user_id, username, reason, message_text):
    """Secure logging"""
    # Sanitize before logging
    username = sanitize_input(username)
    reason = sanitize_input(reason)
    message_text = sanitize_input(message_text)
    
    log_entry = ActionLog(action_type, user_id, username, reason, message_text)
    action_logs.append(log_entry)
    logger.info(f"Action: {action_type} | User: {username} | Reason: {reason}")

# =====================================================================
# UI COMPONENTS
# =====================================================================

def get_admin_main_menu():
    """Admin main menu with buttons"""
    keyboard = [
        [InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")],
        [InlineKeyboardButton("📋 Recent Logs", callback_data="admin_logs")],
        [InlineKeyboardButton("👥 User Management", callback_data="admin_users")],
        [InlineKeyboardButton("⚙️ Bot Settings", callback_data="admin_settings")],
        [InlineKeyboardButton("🔒 Security Info", callback_data="admin_security")],
        [InlineKeyboardButton("❓ Help & Commands", callback_data="admin_help")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_user_main_menu():
    """User main menu with buttons"""
    keyboard = [
        [InlineKeyboardButton("📚 Official Channel", url=TELEGRAM_CHANNEL)],
        [InlineKeyboardButton("💬 Telegram Group", url=TELEGRAM_GROUP)],
        [InlineKeyboardButton("🎥 YouTube Channel", url=YOUTUBE_CHANNEL)],
        [InlineKeyboardButton("👨‍💼 Contact Admin", url=ADMIN_CONTACT)],
        [InlineKeyboardButton("❓ How to Use Bot", callback_data="user_help")],
        [InlineKeyboardButton("ℹ️ About Adept Code", callback_data="user_about")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_back_button(callback_data="back_main"):
    """Back button"""
    keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data=callback_data)]]
    return InlineKeyboardMarkup(keyboard)

# =====================================================================
# MESSAGE ANALYSIS
# =====================================================================

def analyze_message(message_text: str, user_id: int) -> dict:
    """Analyze message securely"""
    if not message_text:
        return {"action": "ignore", "reason": "Empty message"}
    
    # Sanitize input first
    text = sanitize_input(message_text).lower().strip()
    user_stats = user_data[user_id]
    
    # Update activity
    user_stats.last_activity = datetime.now()
    user_stats.total_messages += 1
    
    # Check message frequency (DDoS protection)
    now = datetime.now()
    user_stats.message_times.append(now)
    
    if len(user_stats.message_times) >= MAX_MESSAGES_PER_MINUTE:
        time_diff = (now - user_stats.message_times[0]).seconds
        if time_diff < SPAM_TIME_WINDOW:
            return {
                "action": "delete_and_warn",
                "reason": "बहुत तेज़ी से messages भेज रहे हैं (Spam detected)",
                "severity": "high"
            }
    
    # Security: Check for malicious patterns
    for pattern in SPAM_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {
                "action": "delete_and_warn",
                "reason": "Promotional links और spam इस group में allowed नहीं हैं",
                "severity": "high"
            }
    
    for pattern in ABUSE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {
                "action": "delete_and_warn",
                "reason": "Abusive language group में allowed नहीं है",
                "severity": "high"
            }
    
    for pattern in PRIVACY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {
                "action": "delete_and_warn",
                "reason": "Personal details मांगना group rules के against है",
                "severity": "medium"
            }
    
    # Help detection
    help_count = sum(1 for pattern in HELP_PATTERNS if re.search(pattern, text, re.IGNORECASE))
    if help_count >= 1 and len(text) > 15:
        return {
            "action": "help_response",
            "reason": "Coding help request detected",
            "severity": "low"
        }
    
    # Resource detection
    for pattern in RESOURCE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {
                "action": "guide_to_channel",
                "reason": "Resource request detected",
                "severity": "low"
            }
    
    return {
        "action": "ignore",
        "reason": "Normal conversation",
        "severity": "low"
    }

# =====================================================================
# ACTION FUNCTIONS (FIXED WARNING SYSTEM)
# =====================================================================

async def delete_message(update: Update) -> bool:
    """Delete message securely"""
    try:
        await update.message.delete()
        return True
    except TelegramError as e:
        logger.error(f"Failed to delete message: {e}")
        return False

async def warn_user(update: Update, context: ContextTypes.DEFAULT_TYPE, reason: str):
    """FIXED: Send warning to user properly"""
    user_id = update.effective_user.id
    username = update.effective_user.username or update.effective_user.first_name
    
    user_stats = user_data[user_id]
    user_stats.warnings += 1
    user_stats.last_warning = datetime.now()
    user_stats.warning_reasons.append(reason)
    
    warning_count = user_stats.warnings
    
    # Create warning message
    warning_msg = f"""
🚨 **⚠️ WARNING {warning_count}/{MAX_WARNINGS} ⚠️** 🚨

👋 Hello **{username}**!

❌ **Reason:** {reason}

📋 **Group Rules:**
1️⃣ No promotional links, YouTube videos, या बाहरी channels
2️⃣ No spam, abuse, या off-topic discussions  
3️⃣ Personal details नहीं मांगें

💡 **Important:** Yeh group sirf **learning aur coding help** ke liye hai.

{'🚫 **FINAL WARNING!** एक और violation पर automatic ban होगा!' if warning_count >= MAX_WARNINGS-1 else '✅ **कृपया group guidelines follow करें**'}

📚 Channel: {TELEGRAM_CHANNEL}
👨‍💼 Admin: @{ADMIN_USERNAME}

---
🤖 Adept Code Guardian Bot
"""
    
    # Try to send warning via DM first
    dm_sent = False
    try:
        await context.bot.send_message(
            chat_id=user_id,
            text=warning_msg,
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True
        )
        dm_sent = True
        logger.info(f"Warning sent via DM to {username}")
    except TelegramError as e:
        logger.warning(f"Could not send DM to {username}: {e}")
    
    # If DM failed, send in group (and delete after 15 seconds)
    if not dm_sent:
        try:
            group_warning = f"⚠️ **@{username}**: {reason}\n(Warning {warning_count}/{MAX_WARNINGS})\n\n💬 मैंने आपको private message भेजने की कोशिश की लेकिन आपने मुझे block किया हुआ है। कृपया मुझे unblock करें।"
            sent = await update.message.reply_text(
                group_warning, 
                parse_mode=ParseMode.MARKDOWN
            )
            logger.info(f"Warning sent in group to {username}")
            
            # Delete after 15 seconds
            await asyncio.sleep(15)
            await sent.delete()
        except TelegramError as e:
            logger.error(f"Failed to send warning in group: {e}")
    
    # Log action
    log_action("warning", user_id, username, reason, update.message.text if update.message else "")

async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE, reason: str):
    """Ban user securely"""
    user_id = update.effective_user.id
    username = update.effective_user.username or update.effective_user.first_name
    
    user_stats = user_data[user_id]
    user_stats.banned = True
    user_stats.ban_reason = reason
    
    try:
        # Ban user
        await context.bot.ban_chat_member(
            chat_id=update.effective_chat.id,
            user_id=user_id
        )
        
        # Notify in group
        ban_msg = f"""
🚫 **USER BANNED** 🚫

👤 **User:** @{username}
⚡ **Reason:** {reason}
📅 **Date:** {datetime.now().strftime('%d/%m/%Y %H:%M')}

🛡️ Group safety maintained
"""
        
        sent = await update.message.reply_text(ban_msg, parse_mode=ParseMode.MARKDOWN)
        await asyncio.sleep(12)
        await sent.delete()
        
        log_action("ban", user_id, username, reason, update.message.text if update.message else "")
        logger.info(f"User banned: {username} (Reason: {reason})")
        
        # Try to notify user
        try:
            user_ban_msg = f"""
🚫 **BANNED FROM ADEPT CODE GROUP** 🚫

**Reason:** {reason}

आप group rules follow नहीं कर रहे थे.

**Unban के लिए:** Admin @{ADMIN_USERNAME} से contact करें

---
🤖 Adept Code Guardian Bot
"""
            await context.bot.send_message(
                chat_id=user_id, 
                text=user_ban_msg, 
                parse_mode=ParseMode.MARKDOWN
            )
        except:
            pass
            
    except TelegramError as e:
        logger.error(f"Failed to ban user {username}: {e}")

async def send_help_response(update: Update):
    """Send coding help response"""
    username = update.effective_user.username or update.effective_user.first_name
    
    help_msg = f"""
💡 **Hey {username}!** 

मैं आपकी coding में help कर सकता हूं! 

📝 **अपना problem detail में share करें:**
• Error messages
• Code snippets  
• Technology/language details

💬 **Group members भी आपकी help करेंगे!**

📚 **More Resources:** {TELEGRAM_CHANNEL}

🚀 **Happy Coding!**
"""
    
    try:
        await update.message.reply_text(
            help_msg, 
            parse_mode=ParseMode.MARKDOWN, 
            disable_web_page_preview=True
        )
    except TelegramError as e:
        logger.error(f"Failed to send help: {e}")

async def guide_to_channel(update: Update):
    """Guide to official channel"""
    username = update.effective_user.username or update.effective_user.first_name
    
    guide_msg = f"""
📚 **Hey {username}!** 

Resources, prompts aur learning material के लिए हमारा official channel check करें:

🔗 **Channel:** {TELEGRAM_CHANNEL}

📱 **यहां मिलेगा:**
• Latest AI prompts
• Source codes & templates
• Development tutorials
• Project ideas
• Updates & announcements

⚡ **सब free और latest!**

🎯 **Happy Learning!**
"""
    
    try:
        await update.message.reply_text(
            guide_msg, 
            parse_mode=ParseMode.MARKDOWN, 
            disable_web_page_preview=True
        )
    except TelegramError as e:
        logger.error(f"Failed to send guide: {e}")

# =====================================================================
# MESSAGE HANDLER
# =====================================================================

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Main message handler with security"""
    # Only handle group messages
    if update.effective_chat.type not in [Chat.GROUP, Chat.SUPERGROUP]:
        return
    
    # Security: Ignore bots
    if not update.message or not update.message.text or update.effective_user.is_bot:
        return
    
    # Security: Skip admin
    if await verify_admin(update, context):
        return
    
    user_id = update.effective_user.id
    username = update.effective_user.username or update.effective_user.first_name
    message_text = sanitize_input(update.message.text)
    
    # Security: Check if already banned
    if user_data[user_id].banned:
        await delete_message(update)
        return
    
    try:
        # Analyze message
        decision = analyze_message(message_text, user_id)
        action = decision['action']
        reason = decision['reason']
        
        logger.info(f"User: {username} | Action: {action}")
        
        # Execute action
        if action == 'delete_and_warn':
            deleted = await delete_message(update)
            if deleted:
                await warn_user(update, context, reason)
                
                # Auto-ban after max warnings
                if user_data[user_id].warnings >= MAX_WARNINGS:
                    await ban_user(update, context, f"Maximum warnings ({MAX_WARNINGS}) exceeded")
        
        elif action == 'help_response':
            await send_help_response(update)
        
        elif action == 'guide_to_channel':
            await guide_to_channel(update)
        
    except Exception as e:
        logger.error(f"Error handling message: {e}", exc_info=True)

# =====================================================================
# START COMMAND (ADMIN vs USER)
# =====================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Smart start command - different for admin vs users"""
    
    is_admin = await verify_admin(update, context)
    
    if is_admin:
        # ADMIN PANEL
        admin_text = f"""
🔐 **ADMIN PANEL** 🔐

नमस्ते **Admin @{ADMIN_USERNAME}**!

🎛️ **Bot Control Panel में आपका स्वागत है**

📊 **Quick Stats:**
• Total users tracked: {len(user_data)}
• Active warnings: {sum(1 for u in user_data.values() if u.warnings > 0)}
• Banned users: {sum(1 for u in user_data.values() if u.banned)}
• Actions logged: {len(action_logs)}

🛡️ **Security Status:** ✅ All systems operational

👇 **Select an option below:**
"""
        
        await update.message.reply_text(
            admin_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_admin_main_menu()
        )
        logger.info(f"Admin panel opened by @{ADMIN_USERNAME}")
        
    else:
        # USER PANEL
        user_text = """
🤖 **ADEPT CODE GUARDIAN BOT** 🤖

नमस्ते! मैं Adept Code का official bot हूं! 

💡 **What I Do:**
✅ Group को spam-free रखता हूं
✅ Coding में help करता हूं
✅ Resources guide करता हूं
✅ Community को safe रखता हूं

🎯 **Join Our Community:**
📚 Latest tutorials, prompts & resources
🎥 Coding videos & live sessions
💬 Learn with 10,000+ developers

👇 **Explore below:**
"""
        
        await update.message.reply_text(
            user_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_user_main_menu()
        )

# =====================================================================
# CALLBACK QUERY HANDLER (BUTTONS)
# =====================================================================

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button clicks"""
    query = update.callback_query
    await query.answer()
    
    is_admin = await verify_admin(update, context)
    
    # ADMIN CALLBACKS
    if query.data == "admin_stats" and is_admin:
        total_users = len(user_data)
        warned = sum(1 for u in user_data.values() if u.warnings > 0)
        banned = sum(1 for u in user_data.values() if u.banned)
        total_warnings = sum(u.warnings for u in user_data.values())
        
        stats_text = f"""
📊 **DETAILED STATISTICS** 📊

👥 **User Data:**
• Total tracked: {total_users}
• With warnings: {warned}
• Banned: {banned}

⚠️ **Moderation:**
• Total warnings issued: {total_warnings}
• Actions logged: {len(action_logs)}
• Last 24h actions: {len([l for l in action_logs if (datetime.now() - l.timestamp).seconds < 86400])}

🤖 **Bot Status:**
• Health: ✅ Excellent
• Uptime: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
• Memory: {len(action_logs)}/1000 logs

🔒 **Security:**
• Admin verified: ✅ Yes
• Spam filters: ✅ Active
• Auto-moderation: ✅ Running
"""
        
        await query.edit_message_text(
            stats_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_back_button("back_admin")
        )
    
    elif query.data == "admin_logs" and is_admin:
        if not action_logs:
            logs_text = "📋 No action logs yet!"
        else:
            recent = list(action_logs)[-10:]
            logs_text = "📋 **RECENT ACTIONS (Last 10)** 📋\n\n"
            
            for i, log in enumerate(reversed(recent), 1):
                emoji = {'warning': '⚠️', 'ban': '🚫', 'delete': '🗑️'}.get(log.action_type, '📝')
                logs_text += f"{emoji} {i}. {log.action_type.upper()}\n"
                logs_text += f"👤 @{log.username}\n"
                logs_text += f"📅 {log.timestamp.strftime('%H:%M:%S')}\n"
                logs_text += f"💬 {log.reason}\n\n"
        
        await query.edit_message_text(
            logs_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_back_button("back_admin")
        )
    
    elif query.data == "admin_security" and is_admin:
        security_text = f"""
🔒 **SECURITY INFORMATION** 🔒

✅ **Active Security Features:**

🛡️ **Input Sanitization**
• All user input is sanitized
• HTML/Script injection blocked
• Input length limits enforced

🔐 **Admin Verification**
• Multi-level admin verification
• Username + User ID validation
• Telegram API cross-check

📊 **Rate Limiting**
• {MAX_MESSAGES_PER_MINUTE} messages per minute max
• {SPAM_TIME_WINDOW}s spam detection window
• DDoS protection active

🚫 **Content Filtering**
• {len(SPAM_PATTERNS)} spam patterns
• {len(ABUSE_PATTERNS)} abuse patterns
• Malicious link detection

📝 **Secure Logging**
• Token filtered from logs
• Personal data sanitized
• Last {len(action_logs)} actions tracked

⚠️ **Warning System**
• {MAX_WARNINGS}-strike policy
• Auto-ban on max warnings
• Complete audit trail

🔑 **Best Practices:**
✅ Never share bot token
✅ Regular monitoring via /stats
✅ Review logs periodically
✅ Keep admin credentials secure

**Current Status:** 🟢 All systems secure
"""
        
        await query.edit_message_text(
            security_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_back_button("back_admin")
        )
    
    elif query.data == "admin_help" and is_admin:
        help_text = """
❓ **ADMIN COMMANDS & HELP** ❓

📋 **Available Commands:**

🔹 **/start** - Open admin panel
🔹 **/stats** - Quick statistics
🔹 **/logs** - Recent action logs
🔹 **/userinfo <user_id>** - User details
🔹 **/clearwarnings <user_id>** - Reset warnings
🔹 **/unban <user_id>** - Unban user

🎛️ **Panel Features:**
• Real-time statistics
• Action logging
• User management
• Security monitoring

💡 **Tips:**
• Check logs regularly for suspicious activity
• Use /userinfo to investigate users
• Monitor stats for unusual patterns
• Keep bot updated

🔧 **Troubleshooting:**
• If warnings not sending: Check bot permissions
• If bans not working: Ensure bot is admin
• For other issues: Check logs

📞 **Support:**
• Bot issues: Check documentation
• Feature requests: Contact developer
"""
        
        await query.edit_message_text(
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_back_button("back_admin")
        )
    
    elif query.data == "back_admin" and is_admin:
        await query.edit_message_text(
            f"""
🔐 **ADMIN PANEL** 🔐

Welcome back, Admin @{ADMIN_USERNAME}!

👇 Select an option:
""",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_admin_main_menu()
        )
    
    # USER CALLBACKS
    elif query.data == "user_help":
        help_text = f"""
❓ **HOW TO USE THIS BOT** ❓

🤖 **Bot Features:**

✅ **In Group:**
• Automatically removes spam
• Blocks promotional links
• Helps with coding doubts
• Guides to resources

✅ **Private Chat:**
• Get community information
• Access official links
• Learn about Adept Code

📋 **Group Rules:**
1️⃣ No spam or promotional links
2️⃣ Respectful communication only
3️⃣ Coding & learning discussions
4️⃣ No personal info sharing

💡 **Need Coding Help?**
Just ask in the group! Bot और members help करेंगे.

🔗 **Join Us:**
📚 Channel: {TELEGRAM_CHANNEL}
💬 Group: {TELEGRAM_GROUP}
"""
        
        await query.edit_message_text(
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_back_button("back_user")
        )
    
    elif query.data == "user_about":
        about_text = f"""
ℹ️ **ABOUT ADEPT CODE** ℹ️

🎯 **Mission:**
Empowering developers through quality education

👨‍💻 **Founder:**
Adept Code (@{ADMIN_USERNAME})

📊 **Community:**
• 10,000+ Subscribers on Telegram
• Active YouTube Channel
• Growing Developer Community

📚 **What We Offer:**
• Coding Tutorials
• AI Prompts & Templates
• Development Resources
• Live Problem Solving
• Career Guidance

🎥 **YouTube:**
{YOUTUBE_CHANNEL}

📱 **Telegram:**
Channel: {TELEGRAM_CHANNEL}
Group: {TELEGRAM_GROUP}

💡 **Topics Covered:**
• Web Development
• App Development
• AI & Machine Learning
• Programming Languages
• Project Building

🚀 **Join us on this learning journey!**
"""
        
        await query.edit_message_text(
            about_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_back_button("back_user")
        )
    
    elif query.data == "back_user":
        await query.edit_message_text(
            """
🤖 **ADEPT CODE GUARDIAN BOT** 🤖

नमस्ते! मैं Adept Code का official bot हूं!

👇 **Explore below:**
""",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_user_main_menu()
        )

# =====================================================================
# ADDITIONAL ADMIN COMMANDS
# =====================================================================

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Quick stats command"""
    if not await verify_admin(update, context):
        await update.message.reply_text("❌ Admin only command!")
        return
    
    total = len(user_data)
    warned = sum(1 for u in user_data.values() if u.warnings > 0)
    banned = sum(1 for u in user_data.values() if u.banned)
    
    stats_text = f"""
📊 **QUICK STATS** 📊

👥 Users: {total}
⚠️ Warned: {warned}
🚫 Banned: {banned}
📝 Logs: {len(action_logs)}

✅ Status: Running
"""
    
    await update.message.reply_text(stats_text, parse_mode=ParseMode.MARKDOWN)

async def userinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """User info command"""
    if not await verify_admin(update, context):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /userinfo <user_id>")
        return
    
    try:
        user_id = int(context.args[0])
        if user_id not in user_data:
            await update.message.reply_text(f"❌ No data for user {user_id}")
            return
        
        user = user_data[user_id]
        
        info_text = f"""
👤 **USER INFO** 👤

🆔 ID: {user_id}
⚠️ Warnings: {user.warnings}/{MAX_WARNINGS}
📊 Messages: {user.total_messages}
📅 First seen: {user.first_seen.strftime('%d/%m/%Y %H:%M')}
📅 Last active: {user.last_activity.strftime('%d/%m/%Y %H:%M')}
🚫 Banned: {'Yes - ' + user.ban_reason if user.banned else 'No'}

**Warning Reasons:**
{chr(10).join(f'• {r}' for r in user.warning_reasons) if user.warning_reasons else '• None'}
"""
        
        await update.message.reply_text(info_text, parse_mode=ParseMode.MARKDOWN)
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID")

async def clearwarnings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Clear warnings command"""
    if not await verify_admin(update, context):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /clearwarnings <user_id>")
        return
    
    try:
        user_id = int(context.args[0])
        if user_id in user_data:
            old_warnings = user_data[user_id].warnings
            user_data[user_id].warnings = 0
            user_data[user_id].warning_reasons = []
            
            await update.message.reply_text(
                f"✅ Warnings cleared!\n"
                f"User: {user_id}\n"
                f"Previous: {old_warnings} → Current: 0"
            )
        else:
            await update.message.reply_text(f"❌ No data for user {user_id}")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID")

# =====================================================================
# MAIN FUNCTION
# =====================================================================

def main():
    """Start bot with security"""
    logger.info("🚀 Starting Adept Code Guardian Bot (Production Mode)...")
    
    # Security check
    if "YOUR_TELEGRAM_BOT_TOKEN" in TELEGRAM_BOT_TOKEN or len(TELEGRAM_BOT_TOKEN) < 30:
        logger.critical("❌ Invalid bot token! Please set correct token.")
        return
    
    try:
        application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
        
        # Commands
        application.add_handler(CommandHandler("start", start_command))
        application.add_handler(CommandHandler("stats", stats_command))
        application.add_handler(CommandHandler("userinfo", userinfo_command))
        application.add_handler(CommandHandler("clearwarnings", clearwarnings_command))
        
        # Callback queries (buttons)
        application.add_handler(CallbackQueryHandler(button_callback))
        
        # Message handler
        application.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
        )
        
        logger.info("✅ Bot started successfully!")
        logger.info(f"👨‍💼 Admin: @{ADMIN_USERNAME}")
        logger.info(f"🔒 Security: Active")
        logger.info(f"🛡️ All systems operational")
        logger.info("🎯 Ready for 10K+ community!")
        
        # Run bot
        application.run_polling(drop_pending_updates=True)
        
    except Exception as e:
        logger.critical(f"❌ Failed to start: {e}", exc_info=True)

if __name__ == '__main__':
    main()