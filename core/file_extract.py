"""
Reads the text out of an uploaded file, so it can be scanned for personal data.

Supported: PDF (with a text layer), Word (.docx) and plain text files (txt, md, csv, tsv, json,
jsonl, log, xml, html, yaml). Nothing is OCR'd, so a scanned PDF or a photo is refused with a
clear message instead of being passed along unchecked. Only the extracted text is ever used
afterwards; the original file is never sent anywhere.

This module stands alone on purpose (standard library plus pypdf, no other Jnvoy imports),
because it is run as its own short-lived process: see core/file_reader.py. A file is untrusted
input, and a parser bug or a hostile file must not be able to reach the web server's memory, its
secrets or its disk. The process started for each file:
  - gets no environment variables (no keys, no database address),
  - has a memory ceiling, a CPU-time ceiling and cannot write files,
  - is killed after a deadline.

Run directly, it reads the file from stdin and writes one line of JSON to stdout:
    python -I file_extract.py <filename> <max_chars> <max_pages> <memory_mb> <cpu_seconds>
"""

import io
import json
import re
import sys
import zipfile

# ── limits (the caller passes its own; these are the defaults) ────────────────────────────────
DEFAULT_MAX_CHARS = 200_000          # the same ceiling as POST /v1/scan
DEFAULT_MAX_PAGES = 100
MAX_ZIP_MEMBERS = 5_000
MAX_ZIP_UNCOMPRESSED = 40_000_000    # all parts of a Word file together
MAX_ZIP_RATIO = 200                  # uncompressed / compressed, per part

IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"), (b"II*\x00", "TIFF"), (b"MM\x00*", "TIFF"),
)

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class FileError(Exception):
    """A file that will not be read. `code` is stable and shown to the caller."""

    def __init__(self, code: str, message: str, status: int = 422):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _clean(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL.sub("", text)


def _extension(filename: str) -> str:
    name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


# ── PDF ───────────────────────────────────────────────────────────────────────────────────────

def _count_images(page) -> int:
    """Counts the pictures on a page without decoding them (decoding is slow and can be abused)."""
    try:
        xobjects = page["/Resources"]["/XObject"].get_object()
        return sum(1 for ref in xobjects.values()
                   if ref.get_object().get("/Subtype") == "/Image")
    except Exception:
        return 0


def _read_pdf(data: bytes, max_chars: int, max_pages: int) -> dict:
    from pypdf import PdfReader  # imported here so text files never need it
    from pypdf.errors import PyPdfError

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            # Many PDFs are "encrypted" with an empty password just to block copying.
            if not reader.decrypt(""):
                raise FileError("encrypted_file",
                                "This PDF is password-protected. Remove the password and send it again.")
        page_count = len(reader.pages)
        if page_count > max_pages:
            raise FileError("too_many_pages",
                            f"This PDF has {page_count} pages. The limit is {max_pages}. "
                            "Split it and send the parts separately.", 413)
        parts, pages, empty, images = [], [], [], 0
        offset = 0
        for number, page in enumerate(reader.pages, start=1):
            try:
                text = _clean(page.extract_text() or "")
            except Exception:
                text = ""
            images += _count_images(page)
            if not text.strip():
                empty.append(number)
            start = offset
            chunk = text.strip("\n")
            parts.append(chunk)
            offset += len(chunk) + 2           # the two newlines that join pages
            pages.append({"page": number, "start": start, "end": start + len(chunk)})
            if offset > max_chars + 2:
                raise FileError("file_too_long",
                                f"This file has more than {max_chars:,} characters of text. "
                                "Split it and send the parts separately.", 413)
        try:
            fields = reader.get_fields() or {}
        except Exception:
            fields = {}
        form_lines = []
        for name, field in fields.items():
            value = field.get("/V") if hasattr(field, "get") else None
            if isinstance(value, (str, int, float)) and str(value).strip():
                form_lines.append(f"{name}: {value}")
        text = "\n\n".join(parts)
        if form_lines:
            form_text = _clean("\n".join(form_lines))
            pages.append({"page": None, "start": len(text) + 2, "end": len(text) + 2 + len(form_text),
                          "label": "form fields"})
            text = text + "\n\n" + form_text
        if len(text) > max_chars:
            raise FileError("file_too_long",
                            f"This file has more than {max_chars:,} characters of text. "
                            "Split it and send the parts separately.", 413)
        if not text.strip():
            raise FileError("no_text_layer",
                            "This PDF has no readable text (it looks like a scan or a set of images). "
                            "Scanned documents are not supported yet, so it was not read.")
        return {"format": "pdf", "text": text, "pages": pages, "page_count": page_count,
                "pages_without_text": empty, "images_skipped": images}
    except FileError:
        raise
    except (PyPdfError, ValueError, KeyError, TypeError, IndexError, AttributeError, OSError,
            RecursionError, NotImplementedError):
        raise FileError("unreadable_file", "This PDF could not be read. It may be damaged.")


# ── Word ──────────────────────────────────────────────────────────────────────────────────────

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_DOCX_PARTS = re.compile(
    r"^word/(document|footnotes|endnotes|comments)\.xml$|^word/(header|footer)\d*\.xml$")


def _docx_part_text(raw: bytes) -> str:
    from xml.etree import ElementTree as ET

    # No document type declaration means no entity definitions, which closes the "billion
    # laughs" expansion attack on the standard XML parser.
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise FileError("unreadable_file", "This Word file contains content that is not allowed.")
    del lowered
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise FileError("unreadable_file", "This Word file could not be read. It may be damaged.")
    lines, current = [], []
    for element in root.iter():
        tag = element.tag
        if tag == _W + "t" and element.text:
            current.append(element.text)
        elif tag == _W + "tab":
            current.append("\t")
        elif tag in (_W + "br", _W + "cr"):
            current.append("\n")
        elif tag == _W + "p":
            # A new paragraph starts: close the one before it. Text inside a paragraph is
            # collected by the branches above; closing at the *start* keeps order right for
            # nested paragraphs (text boxes, table cells).
            if current:
                lines.append("".join(current))
                current = []
    if current:
        lines.append("".join(current))
    return "\n".join(lines)


def _read_docx(data: bytes, max_chars: int) -> dict:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise FileError("unreadable_file", "This Word file could not be read. It may be damaged.")
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_MEMBERS:
            raise FileError("unreadable_file", "This Word file has too many parts.")
        total = 0
        for info in infos:
            total += info.file_size
            if info.file_size > 0 and info.compress_size > 0 \
                    and info.file_size / info.compress_size > MAX_ZIP_RATIO and info.file_size > 1_000_000:
                raise FileError("unreadable_file", "This Word file expands to an unsafe size.")
        if total > MAX_ZIP_UNCOMPRESSED:
            raise FileError("unreadable_file", "This Word file expands to an unsafe size.")
        names = {i.filename for i in infos}
        if "word/document.xml" not in names:
            raise FileError("unsupported_file_type",
                            "This archive is not a Word (.docx) document. Other zip files are not supported.",
                            415)
        order = ["word/document.xml"] + sorted(
            n for n in names if n != "word/document.xml" and _DOCX_PARTS.match(n))
        texts = []
        for name in order:
            info = archive.getinfo(name)
            if info.file_size > MAX_ZIP_UNCOMPRESSED:
                raise FileError("unreadable_file", "This Word file expands to an unsafe size.")
            with archive.open(name) as handle:
                raw = handle.read(MAX_ZIP_UNCOMPRESSED + 1)
            if len(raw) > MAX_ZIP_UNCOMPRESSED:
                raise FileError("unreadable_file", "This Word file expands to an unsafe size.")
            part = _clean(_docx_part_text(raw)).strip("\n")
            if part.strip():
                texts.append(part)
            if sum(len(t) for t in texts) > max_chars:
                raise FileError("file_too_long",
                                f"This file has more than {max_chars:,} characters of text. "
                                "Split it and send the parts separately.", 413)
        images = sum(1 for n in names if n.startswith("word/media/"))
    text = "\n\n".join(texts)
    if len(text) > max_chars:
        raise FileError("file_too_long",
                        f"This file has more than {max_chars:,} characters of text. "
                        "Split it and send the parts separately.", 413)
    if not text.strip():
        raise FileError("no_text_layer", "This Word file has no text in it.")
    return {"format": "docx", "text": text, "pages": [], "page_count": None,
            "pages_without_text": [], "images_skipped": images}


# ── plain text ────────────────────────────────────────────────────────────────────────────────

def _read_text(data: bytes, max_chars: int) -> dict:
    if b"\x00" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise FileError("unsupported_file_type",
                        "This looks like a binary file. Send a PDF, a Word (.docx) file or plain text.", 415)
    if data.startswith(b"\xef\xbb\xbf"):
        text = data.decode("utf-8-sig", errors="replace")
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="replace")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("cp1252", errors="replace")
    text = _clean(text)
    if len(text) > max_chars:
        raise FileError("file_too_long",
                        f"This file has more than {max_chars:,} characters of text. "
                        "Split it and send the parts separately.", 413)
    if not text.strip():
        raise FileError("no_text_layer", "This file is empty.")
    return {"format": "text", "text": text, "pages": [], "page_count": None,
            "pages_without_text": [], "images_skipped": 0}


# ── entry point ───────────────────────────────────────────────────────────────────────────────

def extract(filename: str, data: bytes, max_chars: int = DEFAULT_MAX_CHARS,
            max_pages: int = DEFAULT_MAX_PAGES) -> dict:
    """
    Reads the text out of a file. Returns a dict with:
      format, text, pages (page number -> character range, PDFs only), page_count,
      pages_without_text, images_skipped.
    Raises FileError for anything it will not read. The file's type is decided by its first
    bytes, not its name, so renaming a file does not change how it is read.
    """
    if not data:
        raise FileError("empty_file", "The file is empty.", 400)
    for magic, label in IMAGE_MAGIC:
        if data.startswith(magic):
            raise FileError("image_not_supported",
                            f"This is an image ({label}). Images are not supported yet, because the "
                            "text in them cannot be read and checked. It was not read.", 415)
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        raise FileError("image_not_supported",
                        "This is an image (WEBP). Images are not supported yet, because the text in "
                        "them cannot be read and checked. It was not read.", 415)
    if data.lstrip()[:5] == b"%PDF-" or data[:1024].find(b"%PDF-") != -1:
        return _read_pdf(data, max_chars, max_pages)
    if data.startswith(b"PK\x03\x04"):
        return _read_docx(data, max_chars)
    extension = _extension(filename)
    legacy = {"doc": "Old Word (.doc) files", "xls": "Excel files", "xlsx": "Excel files",
              "ppt": "PowerPoint files", "pptx": "PowerPoint files", "odt": "OpenDocument files",
              "rtf": "RTF files"}
    if extension in legacy or data.startswith(b"\xd0\xcf\x11\xe0"):
        what = legacy.get(extension, "This file type")
        raise FileError("unsupported_file_type",
                        f"{what} are not supported. Send a PDF, a Word (.docx) file or plain text.", 415)
    return _read_text(data, max_chars)


# ── the process that runs it ──────────────────────────────────────────────────────────────────

def _limit_this_process(memory_mb: int, cpu_seconds: int) -> None:
    try:
        import resource
    except ImportError:          # not available on Windows; the deadline in the parent still applies
        return
    for name, value in (
        ("RLIMIT_AS", memory_mb * 1024 * 1024),
        ("RLIMIT_CPU", cpu_seconds),
        ("RLIMIT_FSIZE", 0),     # may not create or grow a file
        ("RLIMIT_CORE", 0),
    ):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            pass


def _main(argv: list) -> int:
    try:
        filename = argv[1]
        max_chars, max_pages = int(argv[2]), int(argv[3])
        memory_mb, cpu_seconds = int(argv[4]), int(argv[5])
    except (IndexError, ValueError):
        sys.stdout.write(json.dumps({"ok": False, "code": "bad_arguments",
                                     "message": "bad arguments", "status": 500}))
        return 2
    _limit_this_process(memory_mb, cpu_seconds)
    data = sys.stdin.buffer.read()
    try:
        result = extract(filename, data, max_chars, max_pages)
        out = {"ok": True, **result}
    except FileError as e:
        out = {"ok": False, "code": e.code, "message": e.message, "status": e.status}
    except MemoryError:
        out = {"ok": False, "code": "file_too_complex",
               "message": "This file needs more memory to read than is allowed.", "status": 413}
    except Exception:
        out = {"ok": False, "code": "unreadable_file",
               "message": "This file could not be read.", "status": 422}
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
