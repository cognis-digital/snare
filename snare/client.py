"""HTTP client with on-disk cache and offline mode."""

from __future__ import annotations

import hashlib
import os
import urllib.request

USER_AGENT = "snare/0.1 (+https://cognis.digital)"


class HttpClient:
    def __init__(self, cache_dir=None, offline=False, timeout=60):
        self.cache_dir = cache_dir
        self.offline = offline
        self.timeout = timeout
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    def _cp(self, url):
        if not self.cache_dir:
            return None
        return os.path.join(self.cache_dir, hashlib.sha1(url.encode()).hexdigest()[:16] + ".cache")

    def get(self, url):
        cp = self._cp(url)
        if self.offline:
            if cp and os.path.exists(cp):
                return open(cp, "rb").read()
            raise RuntimeError(f"offline: no cache for {url}")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = r.read()
        if cp:
            open(cp, "wb").write(data)
        return data
