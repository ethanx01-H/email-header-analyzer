"""
config.py - API key management for threat intelligence sources.
Keys are loaded from environment variables or a local config file.
"""

import json
import os
from pathlib import Path

# Config file location (next to the tool)
CONFIG_DIR = Path(__file__).parent
CONFIG_FILE = CONFIG_DIR / "api_keys.json"

# Default config structure
DEFAULT_CONFIG = {
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "abusech_auth_key": "",        # Free at https://auth.abuse.ch/
    "urlhaus_enabled": True,
    "threatfox_enabled": True,
    "dns_lookups_enabled": True,
    "max_iocs_per_source": 10,
    "request_timeout": 10,
}


def load_config() -> dict:
    """Load config from file, with env var overrides."""
    config = DEFAULT_CONFIG.copy()

    # Load from file if exists
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                file_config = json.load(f)
            config.update(file_config)
        except (json.JSONDecodeError, IOError):
            pass

    # Environment variables override file
    env_map = {
        "VT_API_KEY": "virustotal_api_key",
        "ABUSEIPDB_API_KEY": "abuseipdb_api_key",
        "ABUSECH_AUTH_KEY": "abusech_auth_key",
    }
    for env_var, config_key in env_map.items():
        val = os.environ.get(env_var, "")
        if val:
            config[config_key] = val

    return config


def save_config(config: dict):
    """Save config to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_api_key(service: str) -> str:
    """Get API key for a specific service."""
    config = load_config()
    key_map = {
        "virustotal": "virustotal_api_key",
        "abuseipdb": "abuseipdb_api_key",
        "abusech": "abusech_auth_key",
    }
    return config.get(key_map.get(service, ""), "")


def setup_wizard():
    """Interactive setup for API keys."""
    print("Email Header Analysis Tool — API Key Setup")
    print("=" * 50)
    print()
    print("Some features require API keys. Leave blank to skip.")
    print()

    config = load_config()

    # VirusTotal
    print("VirusTotal (https://www.virustotal.com/gui/my-api-key)")
    print("  Free tier: 4 requests/minute, 500/day")
    vt_key = input(f"  API Key [{_mask(config.get('virustotal_api_key', ''))}]: ").strip()
    if vt_key:
        config["virustotal_api_key"] = vt_key

    # AbuseIPDB
    print()
    print("AbuseIPDB (https://www.abuseipdb.com/account/api)")
    print("  Free tier: 1000 checks/day")
    abuse_key = input(f"  API Key [{_mask(config.get('abuseipdb_api_key', ''))}]: ").strip()
    if abuse_key:
        config["abuseipdb_api_key"] = abuse_key

    # abuse.ch (URLhaus + ThreatFox)
    print()
    print("abuse.ch Auth-Key (https://auth.abuse.ch/)")
    print("  Free — covers URLhaus + ThreatFox + MalwareBazaar")
    abusech_key = input(f"  Auth-Key [{_mask(config.get('abusech_auth_key', ''))}]: ").strip()
    if abusech_key:
        config["abusech_auth_key"] = abusech_key

    save_config(config)
    print()
    print(f"Config saved to: {CONFIG_FILE}")
    print("Keys are also read from env vars: VT_API_KEY, ABUSEIPDB_API_KEY, ABUSECH_AUTH_KEY")


def _mask(key: str) -> str:
    """Mask API key for display."""
    if not key:
        return "not set"
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]
