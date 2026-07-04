<div align="center">

# HashBot

**Telegram bot for hashing, password checks, and generation.**

[![Python](https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Telegram](https://img.shields.io/badge/Telegram-bot-26A5E4?style=flat-square&logo=telegram&logoColor=white)](#setup)
[![License](https://img.shields.io/badge/license-MIT-af52de?style=flat-square)](#license)

</div>

---

A lightweight **[Telegram](https://telegram.org/) bot** that hashes text (MD5 / SHA-256), stores per-user history behind a codeword, checks passwords against **Have I Been Pwned**, scores strength with **zxcvbn**, and generates random passwords.

Bot UI messages are in **Russian**. This README is in English.

---

## Commands

| Command | What it does |
|---------|----------------|
| `/start` | Welcome + command list |
| `/help` | Hash usage hint |
| `/hash <algo> <text>` | Hash with `md5` or `sha256` |
| `/history` | Show saved hashes (requires codeword) |
| `/setcode <word>` | Set codeword for history access |
| `/check <password>` | HIBP breach check (k-anonymity API) |
| `/checkzxcvbn` | Interactive zxcvbn strength score |
| `/generate <length>` | Random password |
| `/dev` | Author info |

History is stored in `history_{user_id}.json` on the machine running the bot.

---

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the **API token**.
2. Clone and install:

```bash
git clone https://github.com/krwg/hash-bot.git
cd hash-bot
pip install -r requirements.txt
```

3. Set the token (pick one):

```bash
# Option A — environment variable (recommended)
export TELEGRAM_BOT_TOKEN="your-token-here"
python hash.py

# Option B — edit hash.py and replace YOUR TOKEN
```

4. Run on a machine with internet access (long polling).

---

## Security notes

- **Do not commit** your bot token.
- `/check` uses the [HIBP range API](https://haveibeenpwned.com/API/v3#PwnedPasswords) — only a SHA-1 prefix is sent.
- History files and codewords are local to your server; back them up if you care about retention.
- This is a utility bot, not audited for high-security production use.

---

## Requirements

- Python 3.12+
- Linux, macOS, or Windows
- See `requirements.txt`

---

## License

MIT — portfolio / utility project by [krwg](https://github.com/krwg).
