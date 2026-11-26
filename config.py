"""Параметри AES для навчального проєкту. Не реалізація AES вручну."""
MAGIC = b"ALAB"
VERSION = 2
BLOCK_BITS = 128                     # Фіксована довжина блоку AES (НЕ параметр ключа)
DEFAULT_KEY_BITS = 256
ITERATIONS = 600_000                 # PBKDF2-HMAC-SHA256
SALT_BYTES = 16
NONCE_BYTES_GCM = 12
IV_BYTES = 16
TAG_GCM_BYTES = 16
TAG_HMAC_BYTES = 32
CHUNK_SIZE = 256 * 1024
MAX_HEADER_BYTES = 2048
MAX_ENCRYPTIONS = 100                 # Навчальний ліміт, не стандартна межа GCM
MAX_KEY_AGE_DAYS = 90
MODES = ("gcm", "cbc", "ctr")
