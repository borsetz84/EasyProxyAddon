import logging
import re
import time
from urllib.parse import urlparse, urljoin

import aiohttp
from curl_cffi.requests import AsyncSession

from config import BYPARR_URL, BYPARR_TIMEOUT, get_proxy_for_url, TRANSPORT_ROUTES, GLOBAL_PROXIES
from utils.cookie_cache import CookieCache

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class Settings:
    byparr_url = BYPARR_URL
    byparr_timeout = BYPARR_TIMEOUT

settings = Settings()

_DOOD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

class DoodStreamExtractor:
    """
    DoodStream / PlayMogo extractor.
    """

    def __init__(self, request_headers: dict = None, proxies: list = None):
        self.request_headers = request_headers or {}
        self.base_headers = self.request_headers.copy()
        # Forziamo sempre un User-Agent browser fin dall'inizio
        self.base_headers["User-Agent"] = _DOOD_UA
        self.proxies = proxies or []
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.cache = CookieCache("dood")

    def _get_proxy(self, url: str) -> str | None:
        return get_proxy_for_url(url, TRANSPORT_ROUTES, GLOBAL_PROXIES)

    async def extract(self, url: str, **kwargs):
        parsed = urlparse(url)
        video_id = parsed.path.rstrip("/").split("/")[-1]
        if not video_id:
            raise ExtractorError("Invalid DoodStream URL: no video ID found")

        domain = parsed.netloc
        cached = self.cache.get(domain)
        if cached:
            logger.info(f"DoodStream: Using cached cookies for {domain}")
            try:
                return await self._extract_via_curl_cffi(url, video_id, cookies=cached["cookies"], ua=cached["userAgent"])
            except Exception as e:
                logger.warning(f"DoodStream: Cached cookies failed for {domain}: {e}")

        if settings.byparr_url:
            try:
                return await self._extract_via_byparr(url, video_id)
            except ExtractorError:
                raise

        return await self._extract_via_curl_cffi(url, video_id)

    async def _extract_via_byparr(self, url: str, video_id: str) -> dict:
        endpoint = f"{settings.byparr_url.rstrip('/')}/v1"
        embed_url = url if "/e/" in url else f"https://{urlparse(url).netloc}/e/{video_id}"
        payload = {
            "cmd": "request.get",
            "url": embed_url,
            "maxTimeout": settings.byparr_timeout * 1000,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=settings.byparr_timeout + 15),
            ) as resp:
                if resp.status != 200:
                    raise ExtractorError(f"Byparr HTTP {resp.status}")
                data = await resp.json()

        if data.get("status") != "ok":
            raise ExtractorError(f"Byparr: {data.get('message', 'unknown error')}")

        solution = data.get("solution", {})
        final_url = solution.get("url", embed_url)
        if not final_url.startswith("http"):
            final_url = embed_url
        base_url = f"https://{urlparse(final_url).netloc}"
        html = solution.get("response", "")

        if "pass_md5" not in html:
            raw_cookies = solution.get("cookies", [])
            cookies = {c["name"]: c["value"] for c in raw_cookies}
            # Se Byparr ci dà un UA specifico, lo usiamo per coerenza con i cookie
            ua = solution.get("userAgent", _DOOD_UA)

            if cookies:
                # Salva in cache prima di provare
                self.cache.set(urlparse(url).netloc, cookies, ua)
                
                cf_domain = (
                    next((c.get("domain", "").lstrip(".") for c in raw_cookies if c.get("name") == "cf_clearance"), None)
                    or "playmogo.com"
                )
                retry_url = f"https://{cf_domain}/e/{video_id}"
                proxy = self._get_proxy(retry_url)
                async with AsyncSession() as s:
                    r = await s.get(
                        retry_url,
                        impersonate="chrome",
                        cookies=cookies,
                        headers={"User-Agent": ua, "Referer": f"https://{cf_domain}/"},
                        timeout=20,
                        **({"proxy": proxy} if proxy else {}),
                    )
                    html = r.text
                    base_url = f"https://{urlparse(str(r.url)).netloc}"

            if "pass_md5" not in html:
                return await self._extract_via_curl_cffi(embed_url, video_id)
        else:
            # Abbiamo già l'HTML buono, salviamo comunque i cookie se presenti
            raw_cookies = solution.get("cookies", [])
            if raw_cookies:
                cookies = {c["name"]: c["value"] for c in raw_cookies}
                ua = solution.get("userAgent", _DOOD_UA)
                self.cache.set(urlparse(url).netloc, cookies, ua)

        # Passiamo l'UA risolto per mantenerlo nella chiamata finale
        return await self._parse_embed_html(html, base_url, ua if 'ua' in locals() else _DOOD_UA)

    async def _extract_via_curl_cffi(self, url: str, video_id: str, cookies: dict = None, ua: str = None) -> dict:
        proxy = self._get_proxy(url)
        current_ua = ua or _DOOD_UA
        async with AsyncSession() as s:
            r = await s.get(
                url,
                impersonate="chrome",
                headers={"Referer": f"https://{urlparse(url).netloc}/", "User-Agent": current_ua},
                cookies=cookies or {},
                timeout=30,
                allow_redirects=True,
                **({"proxy": proxy} if proxy else {}),
            )
        html = r.text
        base_url = f"https://{urlparse(str(r.url)).netloc}"

        if "pass_md5" not in html:
            if "turnstile" in html.lower() or "captcha_l" in html:
                raise ExtractorError("DoodStream: site is serving a Turnstile CAPTCHA.")
            raise ExtractorError(f"DoodStream: pass_md5 not found in embed HTML")

        return await self._parse_embed_html(html, base_url, current_ua)

    async def _parse_embed_html(self, html: str, base_url: str, override_ua: str = None) -> dict:
        pass_match = re.search(r"(/pass_md5/[^'\"<>\s]+)", html)
        if not pass_match:
            raise ExtractorError("DoodStream: pass_md5 path not found in embed HTML")

        pass_url = urljoin(base_url, pass_match.group(1))
        
        # FORZIAMO SEMPRE UN UA BROWSER (Ignorando VLC)
        ua = override_ua or _DOOD_UA
        headers = {
            "user-agent": ua,
            "referer": f"{base_url}/",
        }

        proxy = self._get_proxy(pass_url)
        async with AsyncSession() as s:
            r = await s.get(
                pass_url,
                impersonate="chrome",
                headers=headers,
                timeout=20,
                **({"proxy": proxy} if proxy else {}),
            )

        base_stream = r.text.strip()
        if not base_stream or "RELOAD" in base_stream:
            raise ExtractorError("DoodStream: pass_md5 endpoint returned no stream URL.")

        token = re.search(r"token=([^&\s'\"]+)", html).group(1)
        final_url = f"{base_stream}123456789?token={token}&expiry={int(time.time())}"

        return {
            "destination_url": final_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        pass
