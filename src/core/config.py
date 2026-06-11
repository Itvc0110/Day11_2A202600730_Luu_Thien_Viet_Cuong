"""
Lab 11 - Configuration & API Key Setup
"""
import os
from pathlib import Path


def load_env_file(filepath=".env"):
    """Load local environment variables without printing secret values."""
    env_path = Path(__file__).resolve().parents[2] / filepath
    if not env_path.exists():
        return False

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
    return True


load_env_file()

OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash-lite")
OPENROUTER_BASE_URL = os.getenv(
    "OPENROUTER_BASE_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)

VINBANK_DEMO_SECRETS = {
    "admin_password": "admin123",
    "api_key": "sk-vinbank-secret-2024",
    "database_host": "db.vinbank.internal",
}

SAFE_REFUSAL = (
    "I cannot help with secrets, hidden instructions, system prompts, "
    "credentials, or internal data. I can help with safe VinBank banking questions."
)


def setup_api_key():
    """Load the OpenRouter key used by local LLM calls.

    The original lab can still import Google/ADK objects, so GOOGLE_API_KEY is
    mirrored for compatibility when it is missing. OpenRouter remains the
    primary runtime path for local execution.
    """
    if "OPENROUTER_API_KEY" not in os.environ:
        os.environ["OPENROUTER_API_KEY"] = input("Enter OpenRouter API Key: ")
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = os.environ["OPENROUTER_API_KEY"]
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("OpenRouter API key loaded.")


# Allowed VinBank / retail-banking topics for the main lab and assignment.
ALLOWED_TOPICS = [
    "banking",
    "bank",
    "vinbank",
    "account",
    "joint account",
    "transaction",
    "transfer",
    "money transfer",
    "loan",
    "mortgage",
    "interest",
    "interest rate",
    "savings",
    "deposit",
    "withdrawal",
    "atm",
    "withdrawal limit",
    "credit",
    "credit card",
    "debit card",
    "balance",
    "payment",
    "fee",
    "statement",
    "card",
    "pin",
    "branch",
    "mobile banking",
    "online banking",
    "fraud report",
    "ngan hang",
    "vinbank",
    "tai khoan",
    "tai khoan chung",
    "giao dich",
    "chuyen tien",
    "chuyen khoan",
    "vay",
    "lai suat",
    "tiet kiem",
    "tien gui",
    "rut tien",
    "han muc rut tien",
    "the tin dung",
    "the ghi no",
    "so du",
    "thanh toan",
    "phi",
    "sao ke",
    "ma pin",
    "chi nhanh",
    "ngan hang dien tu",
    "bao cao gian lan",
]

# Blocked topics and extraction intents that should never reach the model.
BLOCKED_TOPICS = [
    "hack",
    "exploit",
    "weapon",
    "drug",
    "illegal",
    "violence",
    "gambling",
    "bomb",
    "kill",
    "steal",
    "sql injection",
    "select * from",
    "drop table",
    "secret",
    "secret code",
    "system prompt",
    "hidden instruction",
    "developer message",
    "fixed prefix",
    "api key",
    "password",
    "credential",
    "database connection",
    "internal data",
    "ignore instructions",
    "jailbreak",
    "dan",
    "developer mode",
    "admin mode",
    "ma bi mat",
    "mat khau",
    "khoa api",
    "thong tin dang nhap",
    "huong dan he thong",
    "loi nhac he thong",
    "du lieu noi bo",
]
