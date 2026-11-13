# -*- coding: utf-8 -*-
APP_NAME = "SecureP2PChat"
APP_VERSION = "0.9.30.0"
APP_AUTHOR = "AndromedaHK"

COLORS = {
    "bg_dark": "#0A0F1C",
    "bg_secondary": "#0D1B2A",
    "bg_card": "#12263A",
    "accent": "#00D4FF",
    "accent_hover": "#00B4D8",
    "accent_dark": "#0077B6",
    "text": "#E0E6ED",
    "text_secondary": "#8B9BB4",
    "success": "#00F5A0",
    "danger": "#FF4D6D",
    "warning": "#FFB703",
    "border": "#1B3A4B",
    "bubble_in": "#12263A",
    "bubble_out": "#0077B6",
}

PROTOCOL_VERSION = 3
DEFAULT_PORT = 37421
DEFAULT_SIGNAL_PORT = 37422

MSG_KEY_EXCHANGE = 0x01
MSG_TEXT = 0x02
MSG_IMAGE = 0x03
MSG_ACK = 0x04
MSG_PING = 0x05
MSG_PONG = 0x06
MSG_FILE_START = 0x07
MSG_FILE_CHUNK = 0x08
MSG_FILE_END = 0x09
MSG_TYPING = 0x0A
MSG_DELIVERED = 0x0B
MSG_READ = 0x0C
MSG_RATCHET = 0x0D
MSG_HELLO = 0x0E
MSG_HELLO_ACK = 0x0F
MSG_GROUP_TEXT = 0x10
MSG_GROUP_META = 0x11

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32

SIGNAL_PEER_TTL = 180
SIGNAL_HEARTBEAT = 15
RELAY_POLL_SECONDS = 1.5
RELAY_POLL_JITTER_MIN = 0.8
RELAY_POLL_JITTER_MAX = 3.5

FILE_CHUNK_SIZE = 256 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
    ".mp4", ".mkv", ".avi", ".mov", ".webm",
    ".heic", ".heif", ".tif", ".tiff", ".dng", ".raw", ".cr2", ".cr3",
    ".nef", ".arw", ".orf", ".rw2",
    ".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wma", ".3gp",
    ".txt", ".doc", ".docx", ".pdf", ".odt", ".rtf", ".csv",
}
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".heic", ".heif",
    ".tif", ".tiff", ".dng", ".raw", ".cr2", ".cr3", ".nef", ".arw", ".orf", ".rw2",
}
RISKY_EXTENSIONS = {".doc", ".docx", ".odt", ".rtf"}
PREVIEW_MAX_SIZE = (280, 200)

RATE_LIMIT_MESSAGES_PER_SEC = 20
IDLE_LOCK_SECONDS = 0  # 0 = dezactivat (nu deconectează la idle)
