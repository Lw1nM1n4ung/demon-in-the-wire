from __future__ import annotations

from telegram import KeyboardButton, ReplyKeyboardMarkup


def main_reply_kb(role: str = "viewer") -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton("📊 Status"), KeyboardButton("🔍 Scans")],
        [KeyboardButton("🛡 Findings"), KeyboardButton("💻 Assets")],
    ]
    if role in ("engineer", "owner"):
        rows.append([KeyboardButton("➕ New Scan"), KeyboardButton("📅 Schedules")])
    if role == "owner":
        rows.append([KeyboardButton("🏥 Health"), KeyboardButton("⚙️ Config")])
    rows.append([KeyboardButton("🔰 Menu")])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)
