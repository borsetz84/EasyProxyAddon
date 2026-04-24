import asyncio
import logging
import re
import random
import string
import time
from urllib.parse import urlparse, urljoin

import aiohttp
import cloudscraper
from config import BYPARR_URL, get_proxy_for_url, TRANSPORT_ROUTES, GLOBAL_PROXIES, get_solver_proxy_url
from utils.cookie_cache import CookieCache

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class Settings:
    byparr_url = BYPARR_URL

settings = Settings()

_DOOD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

class DoodStreamExtractor:
    """
    DoodStream / PlayMogo extractor using Network Sniffing (Camoufox) 
    to capture dynamic pass_md5 links directly from traffic.
    """

    def __init__(self, request_headers: dict = None, proxies: list = None):
        self.request_headers = request_headers or {}
        self.base_headers = self.request_headers.copy()
        self.base_headers["User-Agent"] = _DOOD_UA
        self.proxies = proxies or []
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.cache = CookieCache("dood")

    def _get_proxy(self, url: str) -> str | None:
        return get_proxy_for_url(url, TRANSPORT_ROUTES, GLOBAL_PROXIES)

    def _extract_pass_path(self, html: str) -> str | None:
        patterns = [
            r"['\"](/pass_md5/[^'\"]+)['\"]",
            r"\.get\(\s*['\"](/pass_md5/[^'\"]+)['\"]",
            r"(/pass_md5/[A-Za-z0-9\-._]+/[A-Za-z0-9]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)
        return None

    def _extract_token(self, html: str, pass_path: str | None = None) -> str | None:
        if pass_path:
            tail = pass_path.rstrip("/").split("/")[-1]
            if re.fullmatch(r"[A-Za-z0-9]{8,}", tail):
                return tail

        patterns = [
            r"makePlay\(\)\s*\{.*?\?token=([A-Za-z0-9]+)&expiry=",
            r"\?token=([A-Za-z0-9]+)&expiry=",
            r"token=([A-Za-z0-9]+)",
            r"['\"]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]+)['\"]",
            r"window\.[a-z0-9_]+\s*=\s*['\"]([A-Za-z0-9]{20,})['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.I | re.S)
            if match:
                return match.group(1)
        return None

    def _extract_expiry(self, html: str) -> str:
        expiry_match = re.search(r"expiry[:=]\s*['\"]?(\d{10,})['\"]?", html, re.I)
        if expiry_match:
            return expiry_match.group(1)
        if re.search(r"expiry=.*Date\.now\(\)", html, re.I | re.S):
            return str(int(time.time() * 1000))
        return str(int(time.time()))

    async def extract(self, url: str, **kwargs):
        """
        Main extraction entry point. 
        Uses ONLY cloudscraper as requested.
        """
        parsed = urlparse(url)
        video_id = parsed.path.rstrip("/").split("/")[-1]
        if not video_id:
            raise ExtractorError("Invalid DoodStream URL: no video ID found")

        embed_url = url if "/e/" in url else f"https://{parsed.netloc}/e/{video_id}"
        
        # --- PHASE 1: cloudscraper (ONLY) ---
        try:
            logger.info(f"🚀 DoodStream: Trying cloudscraper extraction for {embed_url}")
            # Delay settings to improve bypass success
            scraper = cloudscraper.create_scraper(
                delay=5
            )
            # cloudscraper is synchronous, so we run it in a thread
            r = await asyncio.to_thread(scraper.get, embed_url, headers={"User-Agent": _DOOD_UA}, timeout=30)
            
            if r.status_code == 200:
                html = r.text
                
                # Try to extract the page title to confirm we're on the real page
                title_match = re.search(r"<title>(.*?)</title>", html, re.I)
                if title_match:
                    logger.info(f"🎬 DoodStream Page Title: {title_match.group(1)}")

                # Check for Cloudflare/DDoS protection markers in the HTML
                if "Just a moment..." in html or "DDoS protection" in html or "cf-browser-verification" in html:
                    logger.warning("🛡️ DoodStream: cloudscraper returned 200 but Cloudflare challenge is present.")
                
                # Extract pass_md5 path and token
                # Broad regex for pass_md5
                pass_path = self._extract_pass_path(html)
                token = self._extract_token(html, pass_path)

                if pass_path and token:
                    pass_url = urljoin(embed_url, pass_path)
                    
                    logger.info(f"🔗 Cloudscraper found pass_md5 path: {pass_path}")
                    
                    resp = await asyncio.to_thread(scraper.get, pass_url, headers={"Referer": embed_url}, timeout=30)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        base_stream = resp.text.strip()
                        logger.info("✅ DoodStream: cloudscraper extraction successful!")
                        return self._finalize_extraction(base_stream, html, embed_url, _DOOD_UA)
                    else:
                        logger.warning(f"⚠️ DoodStream: pass_md5 request failed with status {resp.status_code} and content: {resp.text[:100]}")
            
                # Log a snippet of the HTML for debugging if tokens not found
                logger.debug(f"HTML Snippet (first 500 chars): {html[:500]}")
                raise ExtractorError(f"DoodStream: tokens not found in HTML (status 200). CF protected? {'Yes' if 'cf-browser-verification' in html else 'No'}")
            else:
                raise ExtractorError(f"DoodStream: cloudscraper failed to fetch embed page (status {r.status_code})")
                
        except Exception as e:
            logger.error(f"❌ DoodStream: cloudscraper error: {e}")
            raise ExtractorError(f"DoodStream: cloudscraper extraction failed: {e}")

    def _finalize_extraction(self, base_stream: str, html: str, base_url: str, ua: str) -> dict:
        """Constructs the final URL from captured data."""
        if "RELOAD" in base_stream or len(base_stream) < 5:
            raise ExtractorError(f"DoodStream: Captured pass_md5 is invalid ({base_stream[:20]})")

        token = self._extract_token(html)
        if not token:
             raise ExtractorError("DoodStream: token not found in HTML")

        expiry = self._extract_expiry(html)
        rand_str = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        final_url = f"{base_stream}{rand_str}?token={token}&expiry={expiry}"

        logger.info(f"✅ DoodStream successful sniffed extraction: {final_url[:60]}...")

        return {
            "destination_url": final_url,
            "request_headers": {"User-Agent": ua, "Referer": f"{base_url}/", "Accept": "*/*"},
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        pass
