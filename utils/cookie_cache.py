import json
import os
import time
import logging

logger = logging.getLogger(__name__)

class CookieCache:
    def __init__(self, name: str):
        """
        Inizializza la cache con un nome specifico (es. 'dood').
        Il file sarà salvato come 'cookie_cache_{name}.json'.
        """
        self.name = name
        self.filename = f"cookie_cache_{name}.json"

    def get(self, domain: str) -> dict:
        if not os.path.exists(self.filename):
            return None
        try:
            with open(self.filename, "r") as f:
                cache = json.load(f)
            entry = cache.get(domain)
            if entry:
                if entry.get("expiry", 0) > time.time():
                    return entry
                else:
                    logger.debug(f"Cookie cache ({self.name}) expired for domain: {domain}")
        except Exception as e:
            logger.error(f"Error reading cookie cache {self.filename}: {e}")
        return None

    def set(self, domain: str, cookies: dict, ua: str, expiry_delta: int = 7200):
        """
        Salva i cookie e l'UA per un dominio nella cache specifica.
        """
        cache = {}
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r") as f:
                    cache = json.load(f)
            except:
                pass
        
        cache[domain] = {
            "cookies": cookies,
            "userAgent": ua,
            "expiry": time.time() + expiry_delta
        }
        
        try:
            with open(self.filename, "w") as f:
                json.dump(cache, f)
            logger.debug(f"Updated cookie cache {self.filename} for domain: {domain}")
        except Exception as e:
            logger.error(f"Error writing cookie cache {self.filename}: {e}")
