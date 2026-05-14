#!/usr/bin/env python3
"""
SecretFinder - HTTP Fetcher
Handles URL fetching (local + remote), retries, proxy, headers, cookies.
Rewritten & Enhanced by: https://github.com/Xnuvers007/SecretFinder
"""

from __future__ import annotations

import logging
import time
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests_file import FileAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("secretfinder.fetcher")

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class FetchError(Exception):
    pass


class Fetcher:
    """
    Robust HTTP fetcher with:
    - retry logic (exponential back-off)
    - custom headers / cookies / proxy
    - local file:// support
    - rate-limit delay
    """

    def __init__(
        self,
        headers: Optional[dict] = None,
        cookie: str = "",
        proxy: str = "",
        timeout: int = 15,
        retries: int = 3,
        delay: float = 0.0,
        user_agent: str = DEFAULT_UA,
    ):
        self.timeout = timeout
        self.delay   = delay

        # Build session with retry strategy
        self._session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.mount("file://",  FileAdapter())

        # Headers
        self._headers: dict = {
            "User-Agent":      user_agent,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }
        if headers:
            self._headers.update(headers)
        if cookie:
            self._headers["Cookie"] = cookie

        # Proxy
        self._proxies: dict = {}
        if proxy:
            self._proxies = {"http": proxy, "https": proxy}

    def get(self, url: str) -> str:
        """Fetch URL and return content as string."""
        if self.delay > 0:
            time.sleep(self.delay)

        logger.debug("Fetching: %s", url)

        try:
            resp = self._session.get(
                url,
                headers=self._headers,
                proxies=self._proxies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            resp.raise_for_status()
            return resp.content.decode("utf-8", errors="replace")
        except requests.exceptions.RequestException as exc:
            raise FetchError(f"Failed to fetch '{url}': {exc}") from exc

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
