"""
Runs the file reader (core/file_extract.py) as a separate, locked-down process.

A file from a customer is untrusted. Reading one means running parsers over bytes someone else
chose, so it is done in a child process that has no environment variables, a memory ceiling,
a CPU ceiling and no ability to write files, and that is killed after a deadline. If a file
crashes or hangs the reader, only that child dies; the web server and other customers are
unaffected. The file is passed over a pipe and nothing is written to disk.

Settings (environment variables, all optional):
    JNVOY_MAX_FILE_BYTES      largest file accepted, default 5,000,000
    JNVOY_MAX_FILE_CHARS      most text read from one file, default 200,000
    JNVOY_MAX_FILE_PAGES      most PDF pages, default 100
    JNVOY_FILE_TIMEOUT_S      deadline for reading one file, default 20
    JNVOY_FILE_MEMORY_MB      child memory ceiling, default 768
    JNVOY_FILE_WORKERS        files read at the same time, default 2
"""

import asyncio
import base64
import binascii
import json
import os
import sys
from pathlib import Path

from core.file_extract import FileError

_EXTRACT_SCRIPT = str(Path(__file__).with_name("file_extract.py"))


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def max_file_bytes() -> int:
    return _int_env("JNVOY_MAX_FILE_BYTES", 5_000_000)


def max_file_chars() -> int:
    return _int_env("JNVOY_MAX_FILE_CHARS", 200_000)


def max_file_pages() -> int:
    return _int_env("JNVOY_MAX_FILE_PAGES", 100)


def body_limit_for_files() -> int:
    """Largest request body on the routes that take files: base64 makes a file a third bigger."""
    return int(max_file_bytes() * 4 / 3) + 100_000


_slots: dict = {}


def _slot() -> asyncio.Semaphore:
    """One semaphore per running event loop, so tests that make several loops keep working."""
    loop = asyncio.get_running_loop()
    sem = _slots.get(loop)
    if sem is None:
        _slots.clear()
        sem = _slots[loop] = asyncio.Semaphore(_int_env("JNVOY_FILE_WORKERS", 2))
    return sem


def decode_base64(value, what: str = "content_base64") -> bytes:
    """Decodes a base64 string (a data: URL prefix is allowed). Raises FileError(400)."""
    if not isinstance(value, str) or not value.strip():
        raise FileError("invalid_file", f"'{what}' must be the file as a base64 string.", 400)
    value = value.strip()
    if value.startswith("data:"):
        head, _, value = value.partition(",")
        if ";base64" not in head:
            raise FileError("invalid_file", f"'{what}' must be base64.", 400)
    # Refuse before decoding: base64 is 4 characters for every 3 bytes.
    if len(value) > max_file_bytes() * 4 // 3 + 8:
        raise FileError("file_too_large",
                        f"The file is larger than {max_file_bytes():,} bytes.", 413)
    value = "".join(value.split())
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise FileError("invalid_file", f"'{what}' is not valid base64.", 400)


async def read_file(filename: str, data: bytes) -> dict:
    """
    Reads the text out of a file, in a child process. Returns the dict described in
    core/file_extract.extract. Raises FileError, whose `status` is the HTTP status to answer with.
    """
    if len(data) > max_file_bytes():
        raise FileError("file_too_large", f"The file is larger than {max_file_bytes():,} bytes.", 413)
    filename = (filename or "file").replace("\x00", "")[:255] or "file"
    timeout = _int_env("JNVOY_FILE_TIMEOUT_S", 20)

    try:
        await asyncio.wait_for(_slot().acquire(), timeout=timeout)
    except asyncio.TimeoutError:
        raise FileError("file_reader_busy", "Many files are being read right now. Try again shortly.", 503)
    try:
        # A stripped environment: the child must not see keys, database addresses or tokens.
        env = {"PYTHONDONTWRITEBYTECODE": "1"}
        for keep in ("PATH", "SYSTEMROOT", "LANG", "LC_ALL"):
            if keep in os.environ:
                env[keep] = os.environ[keep]
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-B", _EXTRACT_SCRIPT, filename,
            str(max_file_chars()), str(max_file_pages()),
            str(_int_env("JNVOY_FILE_MEMORY_MB", 768)), str(timeout),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=env, cwd="/" if os.name != "nt" else None,
        )
        try:
            out, _ = await asyncio.wait_for(process.communicate(data), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise FileError("file_timeout", "Reading this file took too long.", 422)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
    finally:
        _slot().release()

    try:
        result = json.loads(out.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        # Killed by the memory or CPU ceiling, or crashed: nothing readable came back.
        raise FileError("file_too_complex",
                        "This file could not be read within the safety limits.", 422)
    if not result.get("ok"):
        raise FileError(result.get("code", "unreadable_file"),
                        result.get("message", "This file could not be read."),
                        int(result.get("status", 422)))
    return result


def file_summary(name: str, info: dict) -> dict:
    """What is reported about a file that was read: never its content."""
    out = {"name": name, "format": info["format"], "characters": len(info["text"]),
           "pages": info["page_count"]}
    if info["pages_without_text"]:
        out["pages_without_text"] = info["pages_without_text"]
    if info["images_skipped"]:
        out["images_skipped"] = info["images_skipped"]
    return out
