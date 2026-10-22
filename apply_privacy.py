#!/usr/bin/env python3
"""
Adds the /privacy page.

  * api/proxy_v2.py   : new route GET /privacy (open, no key needed)
  * static/index.html : adds a Privacy link to the footer

static/privacy.html and tests/test_privacy_page.py are copied in by you first (see steps).

Run from the repo root:   python apply_privacy.py
Safe: each edit must match exactly once or nothing is written. Re-running is a no-op.
Undo with: git checkout api/proxy_v2.py static/index.html
"""
import sys
from pathlib import Path

PROXY = Path("api") / "proxy_v2.py"
INDEX = Path("static") / "index.html"
PAGE = Path("static") / "privacy.html"

ROUTE_OLD = (
    '    return {"message": "Jnvoy AI Trust Layer", "docs": "/docs", "version": "2.1.0"}\n'
)
ROUTE_NEW = (
    ROUTE_OLD
    + "\n\n"
    + '@app.get("/privacy", include_in_schema=False)\n'
    + "async def privacy_page():\n"
    + '    _page = os.path.join(_static_dir, "privacy.html")\n'
    + "    if os.path.exists(_page):\n"
    + "        return FileResponse(_page)\n"
    + '    raise HTTPException(status_code=404, detail="Not found")\n'
)
LINK_OLD = '      <a href="/v1/report/compliance">Sample report</a>\n'
LINK_NEW = LINK_OLD + '      <a href="/privacy">Privacy</a>\n'


def main() -> int:
    for p in (PROXY, INDEX, PAGE):
        if not p.exists():
            print(f"Cannot find {p}. Run from the repo root, and copy privacy.html into static/ first.")
            return 1
    proxy = PROXY.read_bytes().decode("utf-8")
    index = INDEX.read_bytes().decode("utf-8")

    if '"/privacy"' in proxy and 'href="/privacy"' in index:
        print("Already applied. Nothing to do.")
        return 0
    if proxy.count(ROUTE_OLD) != 1 or index.count(LINK_OLD) != 1:
        print("A line I expected is not there exactly once. NOTHING WAS CHANGED.")
        print("Send me:  sed -n '84,96p' api/proxy_v2.py   and   sed -n '960,972p' static/index.html")
        return 1
    if "HTTPException" not in proxy:
        print("api/proxy_v2.py does not import HTTPException. NOTHING WAS CHANGED.")
        return 1

    PROXY.write_bytes(proxy.replace(ROUTE_OLD, ROUTE_NEW).encode("utf-8"))
    INDEX.write_bytes(index.replace(LINK_OLD, LINK_NEW).encode("utf-8"))
    print("Applied: /privacy route and footer link.")
    print("Next:  pytest -q")
    return 0


if __name__ == "__main__":
    sys.exit(main())
