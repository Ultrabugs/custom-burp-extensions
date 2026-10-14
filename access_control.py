# -*- coding: utf-8 -*-
# Access Control - Burp Suite extension (broken access control / IDOR replay)
#
# Right-click request(s) anywhere in Burp > Send to Access Control. Paste the
# headers + cookies of one or more other identities into the Identities tab,
# hit Start, and every queued request is replayed once per identity. The
# results table says, per identity, whether the endpoint still answered the
# same thing it answers for you - which is what broken access control looks
# like.
#
# Install: Extender > Extensions > Add > Type: Python > Select this file
# Requires: Jython standalone JAR in Extender > Options > Python Environment
#
# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------
# An identity is a block of raw header lines (paste a whole request straight
# out of Burp - the request line, the body and Host/Content-Length are
# ignored) plus one choice about cookies:
#
#   Use pasted Cookie  - the Cookie header from the paste replaces the
#                        original one. This is the "other user" case.
#   Keep original      - cookies untouched; for header-only swaps such as a
#                        different Authorization: Bearer.
#   No Cookie header   - the Cookie header is removed entirely: unauthenticated.
#   Random cookie      - the original cookie names are kept and every value is
#                        replaced with fresh random hex. Also unauthenticated,
#                        but the request still *looks* well formed, which gets
#                        past front ends that redirect on a missing cookie.
#
# "Strip Authorization / API-key headers" does the same job for bearer tokens
# and API keys, so an unauthenticated probe is really unauthenticated.
#
# One identity is the baseline (ships pre-selected as "Baseline (original
# session)", cookies kept): it is replayed first for each target and every
# other identity's response is scored against it.
#
# ---------------------------------------------------------------------------
# CSRF tokens - why a naive replay lies to you
# ---------------------------------------------------------------------------
# A CSRF token is bound to the session that was issued it. Replay user A's
# request with user B's cookies and the token no longer matches B's session,
# so the app answers 403/419 "invalid CSRF token" - before it ever reaches the
# authorization check. Read as "blocked" that is a false negative, and it is
# the single most common way access control bugs get missed.
#
# Two things here deal with it:
#
# 1. Per-identity token fetch. Enable CSRF handling on the identity, put a raw
#    GET for a page that hands out a token in "Token fetch request" (the
#    Prefill button fills in the selected target's host and path to edit), and
#    before each replay that fetch is sent *with this identity's own cookies
#    and headers*. The token is pulled out with the first regex that matches
#    (one per line - the defaults cover meta tags, hidden inputs and JSON
#    bodies), or straight out of a Set-Cookie by name for double-submit
#    schemes, then written into whichever request headers and body/query/JSON
#    parameters you name - or, with Auto on, into whatever CSRF-shaped header
#    and parameter names the original request already carries. Any cookies the
#    fetch sets (rotated session, XSRF-TOKEN) are merged into the replay too.
#    The fetch exchange is kept per result in the Token fetch viewer tab, so
#    when extraction misses you can see exactly what came back.
#
# 2. CSRF-failure detection. A response that looks like a token rejection is
#    called out as CSRF-FAIL instead of BLOCKED, so a misconfigured token is
#    never silently scored as "the app stopped me".
#
# Single-use tokens: if the app burns a token on use, the baseline replay can
# consume the one in the queued request. Give the baseline identity the same
# token fetch as the others and every replay gets its own fresh token.
#
# Nothing is sent until you press Start, one request at a time, rate limited.

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField, JCheckBox,
    JTextArea, JSplitPane, JMenuItem, SwingUtilities, BorderFactory,
    JRadioButton, ButtonGroup, RowFilter, JTabbedPane, JProgressBar, Box,
    BoxLayout, JList, DefaultListModel, ListSelectionModel,
    JToggleButton
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.text import DefaultHighlighter
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension
from java.util import ArrayList, Comparator
import threading
import time
import random
import re

MAX_RPS = 5.0

SETTING_KEY = "acl.identities.v1"
SETTING_OPT = "acl.options.v1"

# Headers that carry authentication on their own: dropped for the
# unauthenticated identities unless the identity pastes its own.
AUTH_HEADERS = ("Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key",
                "X-Auth-Token", "X-Access-Token", "X-Session-Token",
                "X-Amz-Security-Token", "X-Csrf-Jwt", "Authentication")

# Dropped so a 304 cannot masquerade as an authorization decision.
COND_HEADERS = ("If-None-Match", "If-Modified-Since", "If-Match",
                "If-Unmodified-Since", "If-Range")

# Header/parameter names that look like a CSRF token - used by Auto.
CSRF_NAME_RE = re.compile(r"(?i)(csrf|xsrf|nonce|authenticity_token|"
                          r"verificationtoken|_token$|^token$|form_key)")

DEFAULT_CSRF_REGEX = "\n".join([
    r'name=["\']csrf[-_]token["\']\s+content=["\']([^"\']+)',
    r'name=["\']_?(?:csrf|xsrf)[-_]?token["\'][^>]*?value=["\']([^"\']+)',
    r'name=["\'](?:authenticity_token|csrfmiddlewaretoken|__RequestVerificationToken)["\'][^>]*?value=["\']([^"\']+)',
    r'value=["\']([^"\']+)["\'][^>]*?name=["\']_?(?:csrf|xsrf)[-_]?token["\']',
    r'["\'](?:csrfToken|csrf_token|_token|xsrfToken)["\']\s*:\s*["\']([^"\']+)',
])

# A token rejection, not an authorization decision.
CSRF_FAIL_RE = re.compile(
    r"(?i)(csrf|xsrf|invalid[^.]{0,20}token|token[^.]{0,20}"
    r"(mismatch|invalid|expired|missing|required)|verification failed|"
    r"page expired|419)")
CSRF_FAIL_STATUS = (400, 403, 419, 422, 440)

LOGIN_RE = re.compile(r"(?i)(/login|/log-in|/signin|/sign-in|/auth|/sso|"
                      r"/account/login|/users/sign_in|openid|oauth)")

VERDICT_SEV = {
    "BASELINE":        "base",
    "MARKER FOUND":    "high",
    "IDENTICAL":       "high",
    "NEAR-IDENTICAL":  "high",
    "SIMILAR":         "med",
    "SAME STATUS":     "med",
    "200 (no base)":   "med",
    "CSRF-FAIL":       "warn",
    "RATE LIMITED":    "warn",
    "5xx":             "warn",
    "NO RESPONSE":     "warn",
    "BLOCKED":         "ok",
    "LOGIN REDIRECT":  "ok",
    "404":             "ok",
    "DIFFERENT":       "info",
}
# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
BG     = Color(28,  28,  36)
BG2    = Color(38,  38,  50)
BG3    = Color(50,  50,  65)
FG     = Color(220, 220, 230)
FG_DIM = Color(140, 140, 160)
ACCENT = Color(88,  166, 255)
GREEN  = Color(80,  200, 120)
RED    = Color(255, 80,  80)
YELLOW = Color(255, 200, 60)
BORDER = Color(60,  60,  80)


# ---------------------------------------------------------------------------
# Widget helpers
# ---------------------------------------------------------------------------
def mk_lbl(text, size=12, bold=False, color=None):
    l = JLabel(text)
    l.setForeground(color if color else FG)
    l.setFont(Font("Segoe UI", Font.BOLD if bold else Font.PLAIN, size))
    return l

def mk_btn(text, bg=ACCENT, fg=Color.WHITE):
    b = JButton(text)
    b.setBackground(bg); b.setForeground(fg)
    b.setFocusPainted(False); b.setBorderPainted(False)
    b.setFont(Font("Segoe UI", Font.BOLD, 12))
    return b

def mk_field(text="", w=6):
    f = JTextField(text, w)
    f.setBackground(BG3); f.setForeground(FG); f.setCaretColor(FG)
    f.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(BORDER),
        BorderFactory.createEmptyBorder(3, 6, 3, 6)))
    f.setFont(Font("Courier New", Font.PLAIN, 12))
    return f

def mk_check(text, sel):
    c = JCheckBox(text, sel)
    c.setBackground(BG); c.setForeground(FG)
    c.setFont(Font("Segoe UI", Font.PLAIN, 12))
    return c

def mk_radio(text, sel=False):
    r = JRadioButton(text, sel)
    r.setBackground(BG); r.setForeground(FG)
    r.setFont(Font("Segoe UI", Font.PLAIN, 12)); r.setFocusPainted(False)
    return r

def style_table(t):
    t.setBackground(BG2); t.setForeground(FG)
    t.setGridColor(BORDER); t.setRowHeight(22)
    t.setFont(Font("Courier New", Font.PLAIN, 11))
    t.getTableHeader().setBackground(BG3)
    t.getTableHeader().setForeground(FG)
    t.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 11))
    t.setSelectionBackground(ACCENT); t.setSelectionForeground(Color.WHITE)
    t.setShowHorizontalLines(True); t.setShowVerticalLines(False)

def mk_card(title, inner):
    p = JPanel(BorderLayout())
    p.setBackground(BG2)
    p.setBorder(BorderFactory.createTitledBorder(
        BorderFactory.createLineBorder(BORDER), title,
        0, 0, Font("Segoe UI", Font.BOLD, 11), FG_DIM))
    sc = JScrollPane(inner)
    sc.getViewport().setBackground(BG2); sc.setBorder(None)
    p.add(sc)
    return p

# ---------------------------------------------------------------------------
# Message decoding
#
# What Burp hands back is the response exactly as it came off the wire: the
# body may be chunked, gzip/deflate compressed, or both. None of that is
# JSON or HTML, so the pretty printer had nothing to format and a body
# search had nothing to find.
# ---------------------------------------------------------------------------
def split_head_body(raw):
    for sep in ("\r\n\r\n", "\n\n"):
        i = raw.find(sep)
        if i >= 0:
            return raw[:i], sep, raw[i + len(sep):]
    return raw, "", ""


def header_value(head, name):
    pre = name.lower() + ":"
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if line.lower().startswith(pre):
            return line.split(":", 1)[1].strip()
    return ""


def dechunk(body):
    """Join a chunked body, or None if it does not parse as one."""
    out, i, n = [], 0, len(body)
    while i < n:
        j = body.find("\n", i)
        if j < 0:
            return None
        try:
            size = int(body[i:j].strip().split(";")[0].strip(), 16)
        except Exception:
            return None
        if size == 0:
            break
        start = j + 1
        if start + size > n:
            return None
        out.append(body[start:start + size])
        i = start + size
        while i < n and body[i] in "\r\n":
            i += 1
    return "".join(out) if out else None


def _jvm_gunzip(raw):
    """Jython's zlib silently ignores the gzip wrapper flag, so gzip has to go
    through the JVM. Returns None when not running on Jython."""
    try:
        from java.io import ByteArrayInputStream, ByteArrayOutputStream
        from java.util.zip import GZIPInputStream
        import jarray
    except ImportError:
        return None
    # Bare except on purpose: in Jython a Java exception is NOT a subclass of
    # Python's Exception, so "except Exception" lets a ZipException straight
    # through. GZIPInputStream throws one the moment the body is not gzip.
    try:
        ins = GZIPInputStream(ByteArrayInputStream(raw))
        bos = ByteArrayOutputStream()
        buf = jarray.zeros(8192, "b")
        while True:
            k = ins.read(buf)
            if k < 0:
                break
            bos.write(buf, 0, k)
        ins.close()
        return bos.toString("UTF-8")
    except:
        return None


def decompress_body(body, encoding):
    """Inflate a gzip / deflate body, or None if it is not compressed.

    bytesToString is a latin-1 round trip, so re-encoding recovers the exact
    bytes that came off the wire.
    """
    enc = (encoding or "").lower()
    try:
        raw = body.encode("latin-1")
    except Exception:
        return None
    magic = raw[:2]
    if not isinstance(magic, bytes):
        magic = magic.encode("latin-1")
    looks_gzip = magic == b"\x1f\x8b"
    if not (looks_gzip or "gzip" in enc or "deflate" in enc):
        return None
    if looks_gzip or "gzip" in enc:
        data = _jvm_gunzip(raw)
        if data is not None:
            return data
    import zlib
    for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            out = zlib.decompress(raw, wbits)
            if not isinstance(out, str):
                out = out.decode("utf-8", "replace")
            return out
        except:
            continue
    return None


try:
    _STR_TYPES = (str, unicode)
except NameError:
    _STR_TYPES = (str,)


def charset_decode(body, head):
    """bytesToString decodes as latin-1, so a UTF-8 response comes back as
    mojibake - a thin space arrives as the three characters \xe2\x80\x89.
    Re-decode when the response says UTF-8, or when the bytes are valid UTF-8
    with multibyte sequences in them (which latin-1 text is not, by accident)."""
    try:
        enc = body.encode("latin-1")
    except Exception:
        return body            # already real unicode (inflated through the JVM)
    ct = header_value(head, "Content-Type").lower()
    try:
        dec = enc.decode("utf-8")
    except Exception:
        return body
    if "utf-8" in ct or "utf8" in ct:
        return dec
    return dec if dec != body else body


def decode_message(raw):
    """head + sep + body with the body de-chunked and inflated. Unchanged when
    there is nothing to decode, so it is safe to call on everything."""
    if not raw:
        return raw
    head, sep, body = split_head_body(raw)
    if not sep:
        return raw
    if "chunked" in header_value(head, "Transfer-Encoding").lower():
        dc = dechunk(body)
        if dc is not None:
            body = dc
    inflated = decompress_body(body, header_value(head, "Content-Encoding"))
    if inflated is not None:
        body = inflated
    return head + sep + charset_decode(body, head)


# A lone CR inside a JTextArea sends the renderer back to the start of the line
# and the next glyphs land on top of what is already there - that is what made
# the viewer look like it was drawing over itself. Other C0 controls (from a
# body that is still binary) do the same kind of damage.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def display_text(text):
    if not text:
        return text
    return _CTRL_RE.sub(".", text.replace("\r\n", "\n").replace("\r", "\n"))


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------
def pretty_message(raw):
    if not raw:
        return raw
    head, sep, body = split_head_body(decode_message(raw))
    if not sep:
        return raw
    return head + sep + _pretty_body(body)

MAX_INLINE_STR = 200     # longer markup string values get expanded below the JSON
SYNC_FORMAT_MAX = 16000  # format inline below this; bigger goes to a worker thread
FORMAT_LIMIT    = 200000 # above this, show the message raw - formatting would stall


def _pretty_html(b):
    try:
        x = re.sub(r">\s*<", ">\n<", b.strip())
        out, indent = [], 0
        for line in x.split("\n"):
            line = line.strip()
            if not line:
                continue
            if re.match(r"^</", line):
                indent = max(0, indent - 1)
            out.append("  " * indent + line)
            if re.match(r"^<[^/!?]", line) and not line.endswith("/>") and "</" not in line:
                indent += 1
        return "\n".join(out)
    except Exception:
        return b


def _looks_markup(s):
    t = s.lstrip()[:400].lower()
    return t[:1] == "<" or "<div" in t or "<html" in t or "<span" in t or "<!doctype" in t


def _pretty_json(b):
    """Indent the structure, and pull any long chunk of markup held in a string
    value out below it. An AJAX endpoint that answers {"html": "<div ...80KB>"}
    is otherwise one single line a hundred thousand characters wide, which no
    text area can show and no one can read."""
    import json
    data = json.loads(b)
    blobs = []

    def walk(o, path):
        if isinstance(o, dict):
            return dict((k, walk(o[k], path + [str(k)])) for k in o)
        if isinstance(o, list):
            return [walk(o[i], path + [str(i)]) for i in range(len(o))]
        if isinstance(o, _STR_TYPES) and len(o) > MAX_INLINE_STR and _looks_markup(o):
            name = ".".join(path) or "(body)"
            blobs.append((name, o))
            return "<< %s: %d chars of markup, expanded below >>" % (name, len(o))
        return o

    shaped = walk(data, [])
    txt = json.dumps(shaped, indent=2, separators=(",", ": "), ensure_ascii=False)
    for name, blob in blobs:
        txt += "\n\n" + "=" * 78
        txt += "\n  %s      (%d chars)\n" % (name, len(blob))
        txt += "=" * 78 + "\n"
        txt += _pretty_html(blob)
    return txt


def _pretty_body(body):
    b = body.strip()
    if not b:
        return body
    if b[0] in "{[":
        try:
            return _pretty_json(b)
        except Exception:
            return body
    if b[0] == "<":
        return _pretty_html(b)
    return body

# ---------------------------------------------------------------------------
# Searchable message view
# ---------------------------------------------------------------------------
class _MVSearchDoc(DocumentListener):
    def __init__(self, mv):
        self._mv = mv
    def insertUpdate(self, e):  self._mv.search()
    def removeUpdate(self, e):  self._mv.search()
    def changedUpdate(self, e): self._mv.search()

class MessageView(JPanel):
    def __init__(self, title):
        JPanel.__init__(self, BorderLayout())
        self.setBackground(BG2)
        self.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(BORDER), title,
            0, 0, Font("Segoe UI", Font.BOLD, 11), FG_DIM))
        self._raw = ""; self._matches = []; self._cur = -1
        self._seq = 0
        self._seq_lock = threading.Lock()
        self.area = JTextArea()
        self.area.setBackground(BG2); self.area.setForeground(FG)
        self.area.setCaretColor(FG); self.area.setEditable(False)
        self.area.setLineWrap(False); self.area.setWrapStyleWord(False)
        self.area.setFont(Font("Courier New", Font.PLAIN, 12))
        self.area.setSelectionColor(ACCENT); self.area.setSelectedTextColor(Color.WHITE)
        self._painter = DefaultHighlighter.DefaultHighlightPainter(Color(120, 100, 40))
        sc = JScrollPane(self.area)
        sc.getViewport().setBackground(BG2); sc.setBorder(None)
        self.add(sc, BorderLayout.CENTER)
        self.add(self._bar(), BorderLayout.SOUTH)

    def _bar(self):
        # BorderLayout, not FlowLayout: a FlowLayout in BorderLayout.SOUTH is
        # given one row's height, so when the viewer got narrow the Pretty box
        # wrapped onto an invisible second row and could not be clicked.
        bar = JPanel(BorderLayout(4, 0))
        bar.setBackground(BG3)
        bar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4))

        west = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)); west.setBackground(BG3)
        west.add(mk_lbl("Find:", 11))
        bar.add(west, BorderLayout.WEST)

        self._sf = JTextField("", 10)
        self._sf.setBackground(BG2); self._sf.setForeground(FG); self._sf.setCaretColor(FG)
        self._sf.setFont(Font("Courier New", Font.PLAIN, 12))
        self._sf.getDocument().addDocumentListener(_MVSearchDoc(self))
        self._sf.addActionListener(lambda e: self.find_next())
        bar.add(self._sf, BorderLayout.CENTER)

        east = JPanel(FlowLayout(FlowLayout.LEFT, 3, 0)); east.setBackground(BG3)
        bp = mk_btn(" < ", BG2, FG); bp.addActionListener(lambda e: self.find_prev())
        bn = mk_btn(" > ", BG2, FG); bn.addActionListener(lambda e: self.find_next())
        east.add(bp); east.add(bn)
        self._count = mk_lbl("0/0", 11, color=FG_DIM)
        east.add(self._count)
        self._pretty = JCheckBox("Pretty", True)
        self._pretty.setBackground(BG3); self._pretty.setForeground(FG)
        self._pretty.setToolTipText(
            "Decode the body (chunked / gzip / deflate) and indent JSON or HTML. "
            "Off shows the message as it came off the wire.")
        self._pretty.addActionListener(lambda e: self._render())
        east.add(self._pretty)
        self._wrap = JCheckBox("Wrap", False)
        self._wrap.setBackground(BG3); self._wrap.setForeground(FG)
        self._wrap.setToolTipText(
            "Wrap long lines. Costs real layout time on a big message, and is "
            "rarely needed now that markup held in a JSON string is expanded "
            "into its own block.")
        self._wrap.addActionListener(lambda e: self.area.setLineWrap(
            self._wrap.isSelected()))
        east.add(self._wrap)
        bar.add(east, BorderLayout.EAST)
        return bar

    def set_text(self, raw):
        self._raw = raw or ""
        self._render()

    def search_for(self, text):
        self._sf.setText(text or "")

    def _format(self, raw, pretty):
        """Decode / indent / sanitise. Safe to call off the EDT - it only ever
        touches plain strings."""
        note = ""
        if pretty and len(raw) > FORMAT_LIMIT:
            note = ("[ %d KB response - too large to pretty print, showing it raw. "
                    "Nothing is cut: use Find to reach what you need. ]\n\n"
                    % (len(raw) / 1024))
        elif pretty:
            raw = pretty_message(raw)
        # Normalised even with Pretty off: raw still means "as received", but
        # control characters must not be handed to the renderer.
        return note + display_text(raw)

    def _render(self):
        """Formatting a 54 KB response costs ~85 ms, and on the EDT that is 85 ms
        of frozen UI per click. Anything sizeable is formatted on a worker thread
        and applied when it is ready; a newer selection cancels an older one."""
        with self._seq_lock:
            self._seq += 1
            token = self._seq
        raw    = self._raw
        pretty = self._pretty.isSelected()      # read on the EDT, passed down

        if len(raw) <= SYNC_FORMAT_MAX:
            self._apply(self._format(raw, pretty), token)
            return

        self.area.setText("formatting %d KB ..." % (len(raw) / 1024))
        t = threading.Thread(target=self._bg_render, args=(raw, pretty, token))
        t.setDaemon(True)
        t.start()

    def _bg_render(self, raw, pretty, token):
        try:
            txt = self._format(raw, pretty)
        except Exception as ex:
            txt = "formatting failed: %s" % ex
        except:
            txt = "formatting failed"
        SwingUtilities.invokeLater(lambda: self._apply(txt, token))

    def _apply(self, txt, token):
        with self._seq_lock:
            if token != self._seq:
                return          # a newer selection already won; drop this one
        self.area.setText(txt); self.area.setCaretPosition(0)
        self.search()

    def search(self):
        self.area.getHighlighter().removeAllHighlights()
        self._matches = []; self._cur = -1
        q = self._sf.getText()
        if q:
            text = self.area.getText().lower(); needle = q.lower()
            start = 0
            while True:
                i = text.find(needle, start)
                if i < 0:
                    break
                self._matches.append(i)
                try:
                    self.area.getHighlighter().addHighlight(i, i + len(q), self._painter)
                except Exception:
                    pass
                start = i + len(q)
            if self._matches:
                self._cur = 0; self._focus()
        self._update()

    def find_next(self):
        if self._matches:
            self._cur = (self._cur + 1) % len(self._matches); self._focus()

    def find_prev(self):
        if self._matches:
            self._cur = (self._cur - 1) % len(self._matches); self._focus()

    def _focus(self):
        i = self._matches[self._cur]; q = self._sf.getText()
        self.area.select(i, i + len(q))
        try:
            r = self.area.modelToView(i)
            if r:
                self.area.scrollRectToVisible(r)
        except Exception:
            pass
        self._update()

    def _update(self):
        n = len(self._matches)
        self._count.setText(("%d/%d" % (self._cur + 1, n)) if n else "0/0")


# ---------------------------------------------------------------------------
# Request / header plumbing
# ---------------------------------------------------------------------------
HDR_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
PASTE_IGNORE = ("content-length", "host", "transfer-encoding",
                "connection", "content-encoding")


def split_req(raw):
    """request line, header lines, body. Always rejoined with CRLF."""
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    return lines[0], [l for l in lines[1:] if l.strip()], body


def join_req(reqline, headers, body):
    return "\r\n".join([reqline] + headers) + "\r\n\r\n" + (body or "")


def hdr_get(headers, name):
    pre = name.lower() + ":"
    for hl in headers:
        if hl.lower().startswith(pre):
            return hl.split(":", 1)[1].strip()
    return None


def hdr_set(headers, name, value):
    """Match-replace one header, keeping its position; append when absent."""
    pre, out, done = name.lower() + ":", [], False
    for hl in headers:
        if hl.lower().startswith(pre):
            if not done:
                out.append("%s: %s" % (name, value))
                done = True
            # duplicates of the same header are dropped
        else:
            out.append(hl)
    if not done:
        out.append("%s: %s" % (name, value))
    return out


def hdr_del(headers, name):
    pre = name.lower() + ":"
    return [hl for hl in headers if not hl.lower().startswith(pre)]


def hdr_names(headers):
    out = []
    for hl in headers:
        n = hl.split(":", 1)[0].strip()
        if n:
            out.append(n)
    return out


def parse_header_lines(text):
    """(name, value) for every real header line in a paste. A whole request
    pasted out of Burp is fine: the request line has no colon, the body lines
    are not header-shaped, and Host/Content-Length are dropped because they
    belong to the target, not to the identity."""
    out = []
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        n, _, v = line.partition(":")
        n, v = n.strip(), v.strip()
        if not n or not HDR_NAME_RE.match(n):
            continue
        if n.lower() in PASTE_IGNORE:
            continue
        out.append((n, v))
    return out


def cookie_pairs(value):
    out = []
    for part in (value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        k, eq, v = part.partition("=")
        out.append([k.strip(), v.strip()])
    return out


def cookie_str(pairs):
    return "; ".join("%s=%s" % (k, v) for (k, v) in pairs)


def cookie_merge(value, new_pairs):
    """new_pairs override same-named cookies in place, others are appended."""
    pairs = cookie_pairs(value)
    for (k, v) in new_pairs:
        hit = False
        for pr in pairs:
            if pr[0].lower() == k.lower():
                pr[1] = v
                hit = True
        if not hit:
            pairs.append([k, v])
    return cookie_str(pairs)


def set_cookies_of(resp):
    """(name, value) for every Set-Cookie in a response, attributes dropped."""
    out = []
    head = split_head_body(resp or "")[0]
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if line.lower().startswith("set-cookie:"):
            first = line.split(":", 1)[1].strip().split(";")[0]
            k, eq, v = first.partition("=")
            if k.strip() and eq:
                out.append((k.strip(), v.strip()))
    return out


def rand_cookie_value():
    return "%032x" % random.getrandbits(128)


def status_of(resp):
    if not resp:
        return 0
    try:
        return int(resp.split("\r\n", 1)[0].split(" ")[1])
    except Exception:
        return 0


def body_of(resp):
    """Decoded body only - de-chunked and inflated, never the headers."""
    if not resp:
        return ""
    return split_head_body(decode_message(resp))[2]


def resp_header(resp, name):
    return header_value(split_head_body(resp or "")[0], name)


SHINGLE_N = 5
SHINGLE_CAP = 40000
_WORD_RE = re.compile(r"[a-z0-9_]+")


def shingles(text):
    """Word 5-grams of the first 40 KB. Jaccard over these is cheap, survives
    a reordered JSON object, and does not blow up on a 2 MB page the way a
    character diff does."""
    w = _WORD_RE.findall((text or "").lower()[:SHINGLE_CAP])
    if len(w) < SHINGLE_N:
        return set([tuple(w)]) if w else set()
    return set(tuple(w[i:i + SHINGLE_N]) for i in range(len(w) - SHINGLE_N + 1))


def similarity(a, b):
    """0.0 - 1.0 overlap between two bodies."""
    sa, sb = shingles(a), shingles(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return (inter / float(union)) if union else 1.0


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
COOKIE_MODE_LABEL = {"paste": "pasted Cookie", "keep": "original Cookie",
                     "none": "no Cookie", "random": "random Cookie"}


class Identity(object):
    FIELDS = ("name", "enabled", "baseline", "headers_text", "cookie_mode",
              "strip_auth", "csrf_on", "csrf_auto", "csrf_fetch", "csrf_regex",
              "csrf_cookie", "csrf_headers", "csrf_params", "merge_setcookie")

    def __init__(self, name="New identity", cookie_mode="paste",
                 baseline=False, strip_auth=False, headers_text=""):
        self.name = name
        self.enabled = True
        self.baseline = baseline
        self.headers_text = headers_text
        self.cookie_mode = cookie_mode
        self.strip_auth = strip_auth
        self.csrf_on = False
        self.csrf_auto = True
        self.csrf_fetch = ""
        self.csrf_regex = DEFAULT_CSRF_REGEX
        self.csrf_cookie = ""
        self.csrf_headers = ""
        self.csrf_params = ""
        self.merge_setcookie = True

    def label(self):
        return "%s %s   [%s]" % ("[x]" if self.enabled else "[ ]",
                                 self.name + ("  (baseline)" if self.baseline else ""),
                                 COOKIE_MODE_LABEL.get(self.cookie_mode, self.cookie_mode))

    def to_dict(self):
        return dict((f, getattr(self, f)) for f in self.FIELDS)

    @staticmethod
    def from_dict(d):
        i = Identity()
        for f in Identity.FIELDS:
            if f in d:
                setattr(i, f, d[f])
        return i


def default_identities():
    return [
        Identity("Baseline (original session)", "keep", baseline=True),
        Identity("Other user B (paste headers)", "paste"),
        Identity("Unauthenticated (no cookie)", "none", strip_auth=True),
        Identity("Random cookie value", "random", strip_auth=True),
    ]


# ---------------------------------------------------------------------------
# Widgets / models
# ---------------------------------------------------------------------------
def mk_area(text="", rows=5, cols=78):
    a = JTextArea(text, rows, cols)
    a.setBackground(BG3); a.setForeground(FG); a.setCaretColor(FG)
    a.setFont(Font("Courier New", Font.PLAIN, 12))
    a.setLineWrap(False); a.setTabSize(4)
    return a


def area_card(title, area, h=110):
    sc = JScrollPane(area)
    sc.setBorder(None); sc.getViewport().setBackground(BG3)
    p = JPanel(BorderLayout()); p.setBackground(BG)
    p.setBorder(BorderFactory.createTitledBorder(
        BorderFactory.createLineBorder(BORDER), title,
        0, 0, Font("Segoe UI", Font.BOLD, 11), FG_DIM))
    p.add(sc)
    p.setPreferredSize(Dimension(680, h))
    p.setMaximumSize(Dimension(32767, h))
    p.setAlignmentX(0.0)
    return p


def form_row(*comps):
    r = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
    r.setBackground(BG)
    for c in comps:
        r.add(c)
    r.setMaximumSize(Dimension(32767, 32))
    r.setAlignmentX(0.0)
    return r


def vbox():
    p = JPanel()
    p.setLayout(BoxLayout(p, BoxLayout.Y_AXIS))
    p.setBackground(BG)
    return p


class TargetModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, ["#", "Method", "Host", "Path"], 0)
    def isCellEditable(self, r, c): return False


class ResultModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Method", "Path", "Identity", "Status", "Len", "d Len",
             "Sim %", "Verdict", "Notes"], 0)
    def isCellEditable(self, r, c): return False


class NumComparator(Comparator):
    def compare(self, a, b):
        return cmp(self._f(a), self._f(b))
    def _f(self, v):
        try:
            return float(str(v).strip().replace("+", ""))
        except Exception:
            return float("-inf")


SEV_COLOR = {
    "high": (Color(74, 30, 30),  Color(255, 110, 110)),
    "med":  (Color(70, 60, 28),  YELLOW),
    "warn": (Color(66, 48, 24),  Color(255, 160, 70)),
    "ok":   (Color(32, 56, 36),  GREEN),
    "base": (Color(32, 44, 62),  Color(130, 185, 255)),
    "info": (BG2,                FG_DIM),
}


class ResultRenderer(DefaultTableCellRenderer):
    """Row colour comes from the verdict: red means the other identity got
    what the baseline got."""
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr = table.convertRowIndexToModel(row)
        verd = str(table.getModel().getValueAt(mr, 8) or "")
        bg, fg = SEV_COLOR.get(VERDICT_SEV.get(verd, "info"), (BG2, FG_DIM))
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        else:
            c.setBackground(bg); c.setForeground(fg)
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c


class RowSel(ListSelectionListener):
    def __init__(self, fn):
        self._fn = fn
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            try:
                self._fn()
            except Exception as ex:
                print("[Access Control] selection error: %s" % ex)


# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------
METHOD_RE = re.compile(r"^(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)"
                       r"(\s+HTTP/[\d.]+)?\s*$", re.I)
PCT_RE = re.compile(r"%([0-9a-fA-F]{2})")


def pct_decode(s):
    """XSRF-TOKEN cookies are percent-encoded; the header wants the raw value."""
    try:
        return PCT_RE.sub(lambda m: chr(int(m.group(1), 16)), s or "")
    except Exception:
        return s


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._h  = callbacks.getHelpers()
        self._targets = []      # {raw, svc, method, host, path}
        self._store   = {}      # result# -> dict of messages
        self._rseq    = 1
        self._scan    = False
        self._kept    = 0
        self._lock    = threading.Lock()
        self._ids_cur = -1
        self._ids, self._opt = self._load_settings()

        callbacks.setExtensionName("Access Control")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        if SwingUtilities.isEventDispatchThread():
            self._build()
        else:
            SwingUtilities.invokeAndWait(lambda: self._build())
        print("[Access Control] Loaded - right-click requests > Send to Access Control.")

    # -----------------------------------------------------------------------
    # Settings
    # -----------------------------------------------------------------------
    def _load_settings(self):
        ids, opt = None, {}
        try:
            import json
            raw = self._cb.loadExtensionSetting(SETTING_KEY)
            if raw:
                ids = [Identity.from_dict(d) for d in json.loads(raw)]
            raw = self._cb.loadExtensionSetting(SETTING_OPT)
            if raw:
                opt = json.loads(raw)
        except Exception as ex:
            print("[Access Control] could not restore settings: %s" % ex)
        if not ids:
            ids = default_identities()
        return ids, opt

    def _save_settings(self):
        try:
            import json
            self._commit_identity()
            self._cb.saveExtensionSetting(
                SETTING_KEY, json.dumps([i.to_dict() for i in self._ids]))
            self._cb.saveExtensionSetting(SETTING_OPT, json.dumps({
                "rps": self._f_rps.getText(),
                "marker": self._f_marker.getText(),
                "strip_cond": self._ck_cond.isSelected(),
            }))
        except Exception as ex:
            print("[Access Control] could not save settings: %s" % ex)

    # -----------------------------------------------------------------------
    # UI
    # -----------------------------------------------------------------------
    def _build(self):
        self._tabs = JTabbedPane()
        self._tabs.setBackground(BG); self._tabs.setForeground(FG)
        self._tabs.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._tabs.addTab("  Replay  ", self._build_replay())
        self._tabs.addTab("  Identities  ", self._build_identities())
        self._root = JPanel(BorderLayout())
        self._root.setBackground(BG)
        self._root.add(self._tabs)
        self._cb.addSuiteTab(self)
        self._ids_refresh(0)

    # ---------------------------- Replay tab -------------------------------
    def _build_replay(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBackground(BG)
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        def ctl_row():
            r = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3)); r.setBackground(BG)
            return r

        row1, row2 = ctl_row(), ctl_row()
        bar = JPanel(BorderLayout()); bar.setBackground(BG)
        bar.add(row1, BorderLayout.NORTH); bar.add(row2, BorderLayout.SOUTH)

        row1.add(mk_lbl("Flag responses containing:", 12, True))
        self._f_marker = mk_field(self._opt.get("marker", ""), 24)
        self._f_marker.setToolTipText(
            "Optional. Any response holding this string is reported as MARKER "
            "FOUND. Put something only the other user should ever see in here - "
            "their email, their order id, their account name - and an IDOR "
            "stops being a judgement call.")
        row1.add(self._f_marker)
        self._ck_cond = mk_check("Strip If-None-Match / If-Modified-Since",
                                 self._opt.get("strip_cond", True))
        self._ck_cond.setToolTipText(
            "On (recommended): drop conditional headers so the server cannot "
            "answer 304 Not Modified, which carries no body to compare.")
        row1.add(self._ck_cond)
        row1.add(mk_lbl("Req/sec (max %d):" % int(MAX_RPS)))
        self._f_rps = mk_field(str(self._opt.get("rps", "5")), 4)
        row1.add(self._f_rps)

        self._btn_start = mk_btn("  Start  ", GREEN)
        self._btn_start.addActionListener(lambda e: self._start())
        row2.add(self._btn_start)
        self._btn_stop = mk_btn("  Stop  ", RED)
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(lambda e: self._stop())
        row2.add(self._btn_stop)
        self._prog = JProgressBar(0, 100)
        self._prog.setStringPainted(True); self._prog.setString("Idle")
        self._prog.setPreferredSize(Dimension(240, 22))
        self._prog.setBackground(BG3); self._prog.setForeground(ACCENT)
        row2.add(self._prog)
        row2.add(Box.createHorizontalStrut(10))
        self._tg_hits = JToggleButton("Hits only")
        self._tg_hits.setBackground(BG3); self._tg_hits.setForeground(FG)
        self._tg_hits.setFont(Font("Segoe UI", Font.BOLD, 11))
        self._tg_hits.setFocusPainted(False)
        self._tg_hits.setToolTipText(
            "Show only the rows worth a look: identical / near-identical to the "
            "baseline, a marker hit, or a CSRF failure that needs retesting.")
        self._tg_hits.addActionListener(lambda e: self._apply_filter())
        row2.add(self._tg_hits)
        panel.add(bar, BorderLayout.NORTH)

        # targets (left)
        t_top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t_top.setBackground(BG)
        b_tc = mk_btn("Remove", BG3, FG)
        b_tc.addActionListener(lambda e: self._del_target())
        b_tca = mk_btn("Clear all", BG3, FG)
        b_tca.addActionListener(lambda e: self._clear_targets())
        t_top.add(mk_lbl("Targets", 12, True)); t_top.add(b_tc); t_top.add(b_tca)
        self._t_model = TargetModel()
        self._t_table = JTable(self._t_model)
        style_table(self._t_table)
        for i, w in enumerate([30, 54, 140, 220]):
            self._t_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._t_table.getSelectionModel().addListSelectionListener(
            RowSel(lambda: self._show_target()))
        t_wrap = JPanel(BorderLayout()); t_wrap.setBackground(BG)
        t_wrap.add(t_top, BorderLayout.NORTH)
        t_wrap.add(mk_card("Queued requests", self._t_table), BorderLayout.CENTER)

        # results (right)
        r_top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); r_top.setBackground(BG)
        b_rep = mk_btn("Send to Repeater")
        b_rep.addActionListener(lambda e: self._send_repeater())
        b_rc = mk_btn("Clear results", BG3, FG)
        b_rc.addActionListener(lambda e: self._clear_results())
        r_top.add(mk_lbl("Results", 12, True)); r_top.add(b_rep); r_top.add(b_rc)
        self._r_model = ResultModel()
        self._r_table = JTable(self._r_model)
        style_table(self._r_table)
        self._sorter = TableRowSorter(self._r_model)
        for c in (0, 4, 5, 6, 7):
            self._sorter.setComparator(c, NumComparator())
        self._r_table.setRowSorter(self._sorter)
        rend = ResultRenderer()
        for i in range(self._r_model.getColumnCount()):
            self._r_table.getColumnModel().getColumn(i).setCellRenderer(rend)
        for i, w in enumerate([34, 52, 170, 150, 52, 60, 56, 48, 110, 260]):
            self._r_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._r_table.getSelectionModel().addListSelectionListener(
            RowSel(lambda: self._show_result()))
        r_wrap = JPanel(BorderLayout()); r_wrap.setBackground(BG)
        r_wrap.add(r_top, BorderLayout.NORTH)
        r_wrap.add(mk_card("Replays", self._r_table), BorderLayout.CENTER)

        top = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, t_wrap, r_wrap)
        top.setResizeWeight(0.3); top.setDividerSize(5); top.setBackground(BG)

        # viewers
        self._v_req   = MessageView("Replayed request")
        self._v_resp  = MessageView("Replayed response")
        self._v_base  = MessageView("Baseline response (same target)")
        self._v_fetch = MessageView("Token fetch (request, then response)")
        self._v_tabs = JTabbedPane()
        self._v_tabs.setBackground(BG); self._v_tabs.setForeground(FG)
        self._v_tabs.setFont(Font("Segoe UI", Font.BOLD, 11))
        self._v_tabs.addTab(" Request ", self._v_req)
        self._v_tabs.addTab(" Response ", self._v_resp)
        self._v_tabs.addTab(" Baseline ", self._v_base)
        self._v_tabs.addTab(" Token fetch ", self._v_fetch)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, self._v_tabs)
        split.setResizeWeight(0.42); split.setDividerSize(5); split.setBackground(BG)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # --------------------------- Identities tab ----------------------------
    def _build_identities(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBackground(BG)
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # list + buttons
        self._ids_lm = DefaultListModel()
        self._ids_list = JList(self._ids_lm)
        self._ids_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._ids_list.setBackground(BG2); self._ids_list.setForeground(FG)
        self._ids_list.setFont(Font("Courier New", Font.PLAIN, 12))
        self._ids_list.setSelectionBackground(ACCENT)
        self._ids_list.setSelectionForeground(Color.WHITE)
        self._ids_list.addListSelectionListener(RowSel(lambda: self._ids_select()))

        lb = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2)); lb.setBackground(BG)
        for (txt, fn) in (("Add", self._add_id), ("Copy", self._dup_id),
                          ("Delete", self._del_id), ("On/Off", self._toggle_id)):
            b = mk_btn(txt, BG3, FG)
            b.addActionListener(lambda e, f=fn: f())
            lb.add(b)
        left = JPanel(BorderLayout()); left.setBackground(BG)
        left.add(lb, BorderLayout.NORTH)
        left.add(mk_card("Identities", self._ids_list), BorderLayout.CENTER)
        left.setPreferredSize(Dimension(330, 400))

        # editor
        ed = vbox()
        ed.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0))

        self._f_name = mk_field("", 26)
        self._ck_base = mk_check("Use as baseline", False)
        self._ck_base.setToolTipText(
            "The identity every other one is scored against - normally your own "
            "session, cookies kept as they are. Setting it here clears it "
            "everywhere else.")
        ed.add(form_row(mk_lbl("Name:", 12, True), self._f_name, self._ck_base))

        self._rb_ck = {}
        g = ButtonGroup()
        ckrow = form_row(mk_lbl("Cookies:", 12, True))
        for (key, text, tip) in (
            ("paste", "Use pasted Cookie",
             "The Cookie header in the paste below replaces the original one."),
            ("keep", "Keep original",
             "Leave cookies alone - for header-only swaps such as a different "
             "Authorization: Bearer."),
            ("none", "No Cookie header",
             "Remove the Cookie header entirely: a truly unauthenticated probe."),
            ("random", "Random cookie values",
             "Keep the original cookie names and replace every value with fresh "
             "random hex. Unauthenticated, but well formed enough to get past a "
             "front end that just redirects when a cookie is missing.")):
            rb = mk_radio(text, key == "paste")
            rb.setToolTipText(tip)
            g.add(rb); ckrow.add(rb)
            self._rb_ck[key] = rb
        ed.add(ckrow)

        self._ck_strip = mk_check("Strip Authorization / API-key headers", False)
        self._ck_strip.setToolTipText(
            "Drop %s unless this identity pastes its own. Without this an "
            "\"unauthenticated\" probe can still be carrying a bearer token "
            "from the original request." % ", ".join(AUTH_HEADERS[:4]))
        ed.add(form_row(self._ck_strip))

        self._a_headers = mk_area("", 7)
        self._a_headers.setToolTipText(
            "Paste the other identity's headers here - a whole request copied "
            "out of Burp is fine. The request line, the body, Host and "
            "Content-Length are ignored; everything else replaces or is added "
            "to the original request's headers.")
        ed.add(area_card("Headers + Cookie to send (paste from Burp)",
                         self._a_headers, 150))

        # CSRF block
        self._ck_csrf = mk_check("Handle CSRF tokens for this identity", False)
        self._ck_csrf.setToolTipText(
            "Fetch a token with THIS identity's cookies before each replay and "
            "write it into the request. Without it, a replay of someone else's "
            "token is rejected before the authorization check runs and you get "
            "a false BLOCKED.")
        self._ck_auto = mk_check("Auto (use the names already in the request)", True)
        self._ck_auto.setToolTipText(
            "Write the token into whatever CSRF-shaped header and parameter "
            "names the original request already carries (anything matching "
            "csrf / xsrf / nonce / _token / authenticity_token), on top of any "
            "names you list below.")
        ed.add(form_row(self._ck_csrf, self._ck_auto))

        self._a_fetch = mk_area("", 4)
        self._a_fetch.setToolTipText(
            "A raw request that hands out a token, or just a path. Sent with "
            "this identity's cookies and headers before each replay. Leave it "
            "empty to take the token out of the identity's own cookie jar "
            "instead (double-submit schemes).")
        b_pre = mk_btn("Prefill from selected target", BG3, FG)
        b_pre.addActionListener(lambda e: self._prefill_fetch())
        b_test = mk_btn("Test token fetch", ACCENT)
        b_test.addActionListener(lambda e: self._test_token())
        self._l_test = mk_lbl("", 11, color=FG_DIM)
        ed.add(area_card("Token fetch request (raw, or just a path)",
                         self._a_fetch, 110))
        ed.add(form_row(b_pre, b_test, self._l_test))

        self._a_regex = mk_area("", 5)
        self._a_regex.setToolTipText(
            "One regex per line, first match wins, group 1 is the token. Run "
            "against the decoded fetch response (headers and body).")
        ed.add(area_card("Token extraction regexes (group 1 = token)",
                         self._a_regex, 110))

        self._f_ckname = mk_field("", 18)
        self._f_ckname.setToolTipText(
            "Double-submit cookie schemes: read the token straight out of this "
            "cookie (XSRF-TOKEN, csrftoken, ...) - from the fetch response's "
            "Set-Cookie if there is one, otherwise from the Cookie line you "
            "pasted. Percent-decoded.")
        ed.add(form_row(mk_lbl("Token from cookie:", 12, True), self._f_ckname))

        self._f_chdr = mk_field("", 30)
        self._f_chdr.setToolTipText(
            "Comma-separated header names to set to the token, e.g. "
            "X-CSRF-Token, X-XSRF-TOKEN.")
        ed.add(form_row(mk_lbl("Into headers:", 12, True), self._f_chdr))

        self._f_cpar = mk_field("", 30)
        self._f_cpar.setToolTipText(
            "Comma-separated parameter names to set to the token - matched "
            "against query string, urlencoded body, multipart part names and "
            "JSON keys at any depth, e.g. csrf_token, authenticity_token, "
            "_token.")
        ed.add(form_row(mk_lbl("Into parameters:", 12, True), self._f_cpar))

        self._ck_merge = mk_check("Merge Set-Cookie from the token fetch into the replay", True)
        self._ck_merge.setToolTipText(
            "Carry any cookie the fetch sets into the replayed request - a "
            "rotated session cookie, or the XSRF-TOKEN half of a double-submit "
            "pair. Without this the token and the cookie disagree.")
        ed.add(form_row(self._ck_merge))

        b_save = mk_btn("  Save identity  ", GREEN)
        b_save.addActionListener(lambda e: self._save_id())
        b_copy = mk_btn("Copy CSRF setup to all identities", BG3, FG)
        b_copy.addActionListener(lambda e: self._copy_csrf())
        ed.add(form_row(b_save, b_copy))

        ed_sc = JScrollPane(ed)
        ed_sc.setBorder(None); ed_sc.getViewport().setBackground(BG)
        ed_sc.getVerticalScrollBar().setUnitIncrement(16)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, ed_sc)
        split.setResizeWeight(0.25); split.setDividerSize(5); split.setBackground(BG)
        panel.add(split, BorderLayout.CENTER)

        hint = mk_lbl("Right-click the other user's request anywhere in Burp > "
                      "\"Copy headers to selected identity\" to fill the paste "
                      "box without leaving Burp.", 11, color=FG_DIM)
        panel.add(hint, BorderLayout.SOUTH)
        return panel

    # -----------------------------------------------------------------------
    # Identity list plumbing
    # -----------------------------------------------------------------------
    def _ids_refresh(self, select=None):
        keep = self._ids_list.getSelectedIndex() if select is None else select
        self._ids_lm.clear()
        for i in self._ids:
            self._ids_lm.addElement(i.label())
        if self._ids:
            idx = max(0, min(keep, len(self._ids) - 1))
            self._ids_cur = -1          # the selection event must not commit
            self._ids_list.setSelectedIndex(idx)

    def _ids_select(self):
        idx = self._ids_list.getSelectedIndex()
        if idx == self._ids_cur:
            return
        self._commit_identity()
        self._ids_cur = idx
        if 0 <= idx < len(self._ids):
            self._load_identity(self._ids[idx])

    def _load_identity(self, i):
        self._f_name.setText(i.name)
        self._ck_base.setSelected(bool(i.baseline))
        self._rb_ck.get(i.cookie_mode, self._rb_ck["paste"]).setSelected(True)
        self._ck_strip.setSelected(bool(i.strip_auth))
        self._a_headers.setText(i.headers_text or "")
        self._a_headers.setCaretPosition(0)
        self._ck_csrf.setSelected(bool(i.csrf_on))
        self._ck_auto.setSelected(bool(i.csrf_auto))
        self._a_fetch.setText(i.csrf_fetch or "")
        self._a_regex.setText(i.csrf_regex or DEFAULT_CSRF_REGEX)
        self._f_ckname.setText(i.csrf_cookie or "")
        self._f_chdr.setText(i.csrf_headers or "")
        self._f_cpar.setText(i.csrf_params or "")
        self._ck_merge.setSelected(bool(i.merge_setcookie))
        self._l_test.setText("")

    def _commit_identity(self):
        """Read the editor back into the identity it was loaded from."""
        idx = self._ids_cur
        if not (0 <= idx < len(self._ids)):
            return
        i = self._ids[idx]
        name = self._f_name.getText().strip()
        i.name = name or i.name
        i.headers_text = self._a_headers.getText()
        for key, rb in self._rb_ck.items():
            if rb.isSelected():
                i.cookie_mode = key
        i.strip_auth = self._ck_strip.isSelected()
        i.csrf_on = self._ck_csrf.isSelected()
        i.csrf_auto = self._ck_auto.isSelected()
        i.csrf_fetch = self._a_fetch.getText()
        i.csrf_regex = self._a_regex.getText()
        i.csrf_cookie = self._f_ckname.getText().strip()
        i.csrf_headers = self._f_chdr.getText()
        i.csrf_params = self._f_cpar.getText()
        i.merge_setcookie = self._ck_merge.isSelected()
        if self._ck_base.isSelected():
            for other in self._ids:
                other.baseline = False
            i.baseline = True
        elif i.baseline:
            i.baseline = False

    def _save_id(self):
        self._commit_identity()
        self._ids_refresh(self._ids_cur)
        self._save_settings()

    def _add_id(self):
        self._commit_identity()
        self._ids.append(Identity("Identity %d" % (len(self._ids) + 1)))
        self._ids_refresh(len(self._ids) - 1)

    def _dup_id(self):
        self._commit_identity()
        idx = self._ids_list.getSelectedIndex()
        if 0 <= idx < len(self._ids):
            d = Identity.from_dict(self._ids[idx].to_dict())
            d.name = d.name + " copy"
            d.baseline = False
            self._ids.insert(idx + 1, d)
            self._ids_refresh(idx + 1)

    def _del_id(self):
        idx = self._ids_list.getSelectedIndex()
        if 0 <= idx < len(self._ids):
            self._ids.pop(idx)
            self._ids_cur = -1
            if not self._ids:
                self._ids.append(Identity("Identity 1"))
            self._ids_refresh(min(idx, len(self._ids) - 1))

    def _toggle_id(self):
        self._commit_identity()
        idx = self._ids_list.getSelectedIndex()
        if 0 <= idx < len(self._ids):
            self._ids[idx].enabled = not self._ids[idx].enabled
            self._ids_refresh(idx)

    def _copy_csrf(self):
        self._commit_identity()
        idx = self._ids_list.getSelectedIndex()
        if not (0 <= idx < len(self._ids)):
            return
        src = self._ids[idx]
        n = 0
        for other in self._ids:
            if other is src:
                continue
            for f in ("csrf_on", "csrf_auto", "csrf_fetch", "csrf_regex",
                      "csrf_cookie", "csrf_headers", "csrf_params",
                      "merge_setcookie"):
                setattr(other, f, getattr(src, f))
            n += 1
        self._ids_refresh(idx)
        # after the refresh: reloading the editor clears this label
        self._l_test.setText("CSRF setup copied to %d identity(ies)" % n)

    def _sel_target(self):
        r = self._t_table.getSelectedRow()
        if r < 0:
            r = 0 if self._targets else -1
        if 0 <= r < len(self._targets):
            return self._targets[r]
        return None

    def _prefill_fetch(self):
        e = self._sel_target()
        if not e:
            self._l_test.setText("queue a target first (Send to Access Control)")
            return
        self._a_fetch.setText(
            "GET %s HTTP/1.1\nHost: %s\nAccept: text/html,application/xhtml+xml,*/*\n"
            "Accept-Language: en-US,en;q=0.9\n" % (e["path"] or "/", e["host"]))
        self._a_fetch.setCaretPosition(0)
        self._l_test.setText("edit the path to a page that hands out a token, "
                             "then Test")

    def _test_token(self):
        self._commit_identity()
        idx = self._ids_list.getSelectedIndex()
        e = self._sel_target()
        if not (0 <= idx < len(self._ids)):
            return
        if not e:
            self._l_test.setText("queue a target first - the fetch needs a host")
            return
        ident = self._ids[idx]
        self._l_test.setText("fetching ...")
        t = threading.Thread(target=self._test_token_bg, args=(ident, e))
        t.setDaemon(True); t.start()

    def _test_token_bg(self, ident, entry):
        try:
            token, src, freq, fresp, notes = self._csrf_prepare(entry, ident, 0.0)
            if token:
                msg = "token: %s   (from %s)" % (token[:48], src)
            else:
                msg = "no token found - %s" % ("; ".join(notes) or "check the regexes")
            SwingUtilities.invokeLater(lambda: self._test_done(msg, freq, fresp))
        except Exception as ex:
            SwingUtilities.invokeLater(
                lambda: self._l_test.setText("fetch failed: %s" % ex))

    def _test_done(self, msg, freq, fresp):
        self._l_test.setText(msg)
        if freq or fresp:
            self._v_fetch.set_text((freq or "") + "\r\n\r\n" +
                                   ("-" * 70) + "\r\n\r\n" + (fresp or ""))
            self._v_tabs.setSelectedIndex(3)

    # -----------------------------------------------------------------------
    # Context menu
    # -----------------------------------------------------------------------
    def createMenuItems(self, inv):
        lst = ArrayList()
        a = JMenuItem("Send to Access Control")
        a.addActionListener(lambda e: self._recv(inv))
        lst.add(a)
        b = JMenuItem("Copy headers to selected identity")
        b.addActionListener(lambda e: self._recv_headers(inv))
        lst.add(b)
        return lst

    def _recv(self, inv):
        msgs = inv.getSelectedMessages()
        if not msgs:
            return
        added = 0
        for msg in msgs:
            try:
                req, svc = msg.getRequest(), msg.getHttpService()
                if req is None or svc is None:
                    continue
                raw = self._h.bytesToString(req)
                reqline = split_req(raw)[0]
                parts = reqline.split(" ")
                self._targets.append({
                    "raw": raw, "svc": svc,
                    "method": parts[0] if parts else "?",
                    "host": str(svc.getHost()),
                    "path": (parts[1] if len(parts) > 1 else "/").split("?", 1)[0]})
                e = self._targets[-1]
                self._t_model.addRow([len(self._targets), e["method"],
                                      e["host"], e["path"]])
                added += 1
            except Exception as ex:
                print("[Access Control] load error: %s" % ex)
        if added:
            print("[Access Control] queued %d request(s)" % added)

    def _recv_headers(self, inv):
        """Fill the selected identity's paste box from a request in Burp - the
        point-and-click way to grab the other user's cookies."""
        msgs = inv.getSelectedMessages()
        if not msgs:
            return
        idx = self._ids_list.getSelectedIndex()
        if not (0 <= idx < len(self._ids)):
            return
        try:
            raw = self._h.bytesToString(msgs[0].getRequest())
        except Exception as ex:
            print("[Access Control] copy headers failed: %s" % ex)
            return
        reqline, headers, body = split_req(raw)
        keep = [hl for hl in headers
                if hl.split(":", 1)[0].strip().lower() not in PASTE_IGNORE]
        self._a_headers.setText("\n".join(keep))
        self._a_headers.setCaretPosition(0)
        ident = self._ids[idx]
        if ident.cookie_mode == "keep":
            self._rb_ck["paste"].setSelected(True)
        self._commit_identity()
        self._ids_refresh(idx)
        self._tabs.setSelectedIndex(1)
        print("[Access Control] headers copied into \"%s\"" % ident.name)

    # -----------------------------------------------------------------------
    # Request building
    # -----------------------------------------------------------------------
    def _fix_cl(self, headers, body):
        if hdr_get(headers, "Content-Length") is None and not body:
            return headers
        blen = len(self._h.stringToBytes(body)) if body else 0
        return hdr_set(headers, "Content-Length", "%d" % blen)

    def _apply_identity(self, raw, ident, strip_cond):
        """The original request wearing this identity's headers and cookies."""
        reqline, headers, body = split_req(raw)
        notes = []
        pasted = parse_header_lines(ident.headers_text)
        pasted_lower = set(n.lower() for (n, v) in pasted)
        pasted_cookie = None
        for (n, v) in pasted:
            if n.lower() == "cookie":
                pasted_cookie = v

        if ident.strip_auth:
            for h in AUTH_HEADERS:
                if hdr_get(headers, h) is not None and h.lower() not in pasted_lower:
                    headers = hdr_del(headers, h)
                    notes.append("dropped " + h)

        for (n, v) in pasted:
            if n.lower() == "cookie":
                continue
            headers = hdr_set(headers, n, v)

        mode = ident.cookie_mode
        if mode == "paste":
            if pasted_cookie is not None:
                headers = hdr_set(headers, "Cookie", pasted_cookie)
            else:
                if hdr_get(headers, "Cookie") is not None:
                    headers = hdr_del(headers, "Cookie")
                notes.append("no Cookie line pasted - sent with no cookies")
        elif mode == "none":
            if hdr_get(headers, "Cookie") is not None:
                headers = hdr_del(headers, "Cookie")
        elif mode == "random":
            cur = hdr_get(headers, "Cookie")
            pairs = cookie_pairs(cur) if cur else []
            if pairs:
                for pr in pairs:
                    pr[1] = rand_cookie_value()
            else:
                pairs = [["session", rand_cookie_value()]]
            headers = hdr_set(headers, "Cookie", cookie_str(pairs))

        if strip_cond:
            for h in COND_HEADERS:
                headers = hdr_del(headers, h)

        headers = self._fix_cl(headers, body)
        return join_req(reqline, headers, body), notes

    def _norm_raw(self, txt, host):
        """A raw request out of the fetch box - or a bare path - made sendable."""
        t = (txt or "").strip()
        if not t:
            return ""
        t = t.replace("\r\n", "\n")
        first = t.split("\n", 1)[0].strip()
        m = METHOD_RE.match(first)
        if not m:
            p = first.split()[0] if first.split() else "/"
            if p.lower().startswith("http"):
                mm = re.match(r"https?://[^/]+(/.*)?$", p)
                p = (mm.group(1) or "/") if mm else "/"
            if not p.startswith("/"):
                p = "/" + p
            return join_req("GET %s HTTP/1.1" % p,
                            ["Host: %s" % host,
                             "Accept: text/html,application/xhtml+xml,*/*"], "")
        if not m.group(3):
            t = ("%s %s HTTP/1.1" % (m.group(1).upper(), m.group(2))) + t[len(first):]
        reqline, headers, body = split_req(t.replace("\n", "\r\n"))
        if hdr_get(headers, "Host") is None:
            headers = ["Host: %s" % host] + headers
        headers = self._fix_cl(headers, body)
        return join_req(reqline, headers, body)

    # -----------------------------------------------------------------------
    # CSRF
    # -----------------------------------------------------------------------
    def _build_fetch(self, entry, ident):
        """The token fetch, wearing the identity.

        It starts from the target request with the identity already applied, so
        it inherits that identity's cookies - and its User-Agent, language and
        the rest, which some apps bind the token to. Only the request line and
        any header the fetch box spells out itself are taken from the box; a
        Cookie line there is ignored on purpose, because a token minted for
        anyone other than the identity about to use it is the bug this whole
        feature exists to avoid."""
        fetch_raw = self._norm_raw(ident.csrf_fetch, entry["host"])
        if not fetch_raw:
            return ""
        freqline, fhdrs, fbody = split_req(fetch_raw)
        base_req = self._apply_identity(entry["raw"], ident, True)[0]
        headers = split_req(base_req)[1]
        if not fbody:
            # a GET fetch must not inherit the target's body headers
            headers = hdr_del(headers, "Content-Type")
            headers = hdr_del(headers, "Content-Length")
        for n in hdr_names(headers):
            # the stale token is about to be replaced; it has no business
            # riding along on the request that mints the new one
            if n.lower() != "cookie" and CSRF_NAME_RE.search(n):
                headers = hdr_del(headers, n)
        for hl in fhdrs:
            n, _, v = hl.partition(":")
            n, v = n.strip(), v.strip()
            if n and n.lower() != "cookie":
                headers = hdr_set(headers, n, v)
        if hdr_get(headers, "Host") is None:
            headers = ["Host: %s" % entry["host"]] + headers
        headers = self._fix_cl(headers, fbody)
        return join_req(freqline, headers, fbody)

    def _csrf_prepare(self, entry, ident, interval):
        """Get a token that belongs to THIS identity.

        Returns (token, source, fetch_request, fetch_response, notes). The
        fetch, when there is one, carries the identity's own cookies - that is
        the whole point: a token minted for the identity that is about to use
        it passes the check, so what comes back is the authorization decision
        and not a CSRF rejection."""
        notes, token, src = [], "", ""
        freq = fresp = ""
        want_ck = (ident.csrf_cookie or "").strip().lower()

        fetch_req = self._build_fetch(entry, ident)
        if fetch_req:
            freq = fetch_req
            fresp = self._send(entry["svc"], fetch_req, interval)
            if not fresp:
                notes.append("token fetch got no response")
            else:
                fst = status_of(fresp)
                if fst in (401, 403) or 300 <= fst < 400:
                    notes.append("token fetch itself answered %d - this identity "
                                 "may not be logged in, or the fetch path is wrong"
                                 % fst)
        # 1. straight out of a Set-Cookie the fetch handed back
        if want_ck and fresp:
            for (k, v) in set_cookies_of(fresp):
                if k.lower() == want_ck and v:
                    token, src = pct_decode(v), "Set-Cookie %s" % k
                    break
        # 2. out of the cookie jar this identity already pastes (double submit)
        if not token and want_ck:
            for (n, v) in parse_header_lines(ident.headers_text):
                if n.lower() == "cookie":
                    for (k, cv) in cookie_pairs(v):
                        if k.lower() == want_ck and cv:
                            token, src = pct_decode(cv), "pasted cookie %s" % k
                            break
        # 3. regexes over the decoded fetch response
        if not token and fresp:
            msg = decode_message(fresp)
            for pat in (ident.csrf_regex or DEFAULT_CSRF_REGEX).split("\n"):
                pat = pat.strip()
                if not pat:
                    continue
                try:
                    mm = re.search(pat, msg)
                except Exception as ex:
                    notes.append("bad regex (%s)" % ex)
                    continue
                if mm and mm.groups() and mm.group(1):
                    token, src = mm.group(1), "regex"
                    break
        if not token and (fetch_req or want_ck):
            notes.append("no CSRF token extracted")
        return token, src, freq, fresp, notes

    def _pairs(self, qs):
        res = []
        if qs:
            for part in qs.split("&"):
                k, eq, v = part.partition("=")
                res.append([k, v, bool(eq)])
        return res

    def _rebuild_qs(self, pairs):
        return "&".join(k + ("=" + v if eq else "") for (k, v, eq) in pairs)

    def _set_params(self, qs, names, token):
        """Replace listed parameters in a query string / urlencoded body."""
        low = [n.lower() for n in names]
        pairs, hits = self._pairs(qs), []
        for pr in pairs:
            if pr[0].lower() in low:
                pr[1] = token; pr[2] = True
                hits.append("param " + pr[0])
        return self._rebuild_qs(pairs), hits

    def _set_json_params(self, body, names, token):
        """Replace every matching key at any depth in a JSON body."""
        low = [n.lower() for n in names]
        hits = []
        try:
            import json
            data = json.loads(body)
        except Exception:
            return body, hits

        def walk(o):
            if isinstance(o, dict):
                out = {}
                for k in o:
                    if str(k).lower() in low:
                        out[k] = token
                        hits.append("json " + str(k))
                    else:
                        out[k] = walk(o[k])
                return out
            if isinstance(o, list):
                return [walk(x) for x in o]
            return o
        try:
            return json.dumps(walk(data)), hits
        except Exception:
            return body, hits

    _MP_RE = re.compile(r'name="([^"]+)"\r?\n\r?\n([^\r\n]*)')

    def _set_multipart(self, body, names, token):
        low = [n.lower() for n in names]
        hits = []

        def rep(m):
            if m.group(1).lower() not in low:
                return m.group(0)
            hits.append("part " + m.group(1))
            head = m.group(0)[:m.start(2) - m.start(0)]
            return head + token
        return self._MP_RE.sub(rep, body), hits

    def _auto_names(self, reqline, headers, body):
        """CSRF-shaped parameter names the request already carries."""
        found = []
        parts = reqline.split(" ")
        target = parts[1] if len(parts) > 1 else ""
        for (k, v, eq) in self._pairs(target.partition("?")[2]):
            if k and CSRF_NAME_RE.search(k):
                found.append(k)
        b = (body or "").strip()
        if b[:1] in "{[":
            try:
                import json
                def walk(o):
                    if isinstance(o, dict):
                        for k in o:
                            if CSRF_NAME_RE.search(str(k)):
                                found.append(str(k))
                            walk(o[k])
                    elif isinstance(o, list):
                        for x in o:
                            walk(x)
                walk(json.loads(b))
            except Exception:
                pass
        else:
            for (k, v, eq) in self._pairs(b):
                if k and CSRF_NAME_RE.search(k):
                    found.append(k)
            for m in self._MP_RE.finditer(body or ""):
                if CSRF_NAME_RE.search(m.group(1)):
                    found.append(m.group(1))
        return found

    def _inject_token(self, raw, ident, token):
        """Write the token into every header and parameter it belongs in."""
        reqline, headers, body = split_req(raw)
        hnames = [x.strip() for x in (ident.csrf_headers or "")
                  .replace(";", ",").split(",") if x.strip()]
        pnames = [x.strip() for x in (ident.csrf_params or "")
                  .replace(";", ",").split(",") if x.strip()]
        if ident.csrf_auto:
            for n in hdr_names(headers):
                if n.lower() != "cookie" and CSRF_NAME_RE.search(n) and n not in hnames:
                    hnames.append(n)
            for n in self._auto_names(reqline, headers, body):
                if n not in pnames:
                    pnames.append(n)
        where = []
        for n in hnames:
            headers = hdr_set(headers, n, token)
            where.append("hdr " + n)
        if pnames:
            parts = reqline.split(" ")
            if len(parts) > 1:
                path, q, query = parts[1].partition("?")
                if q:
                    newq, hits = self._set_params(query, pnames, token)
                    parts[1] = path + ("?" + newq if newq else "")
                    reqline = " ".join(parts)
                    where += hits
            b = (body or "").strip()
            if b:
                ct = (hdr_get(headers, "Content-Type") or "").lower()
                if "multipart/" in ct:
                    body, hits = self._set_multipart(body, pnames, token)
                elif "json" in ct or b[:1] in "{[":
                    body, hits = self._set_json_params(body, pnames, token)
                else:
                    body, hits = self._set_params(b, pnames, token)
                where += hits
        headers = self._fix_cl(headers, body)
        return join_req(reqline, headers, body), where

    def _merge_fetch_cookies(self, raw, fresp):
        pairs = set_cookies_of(fresp)
        if not pairs:
            return raw, []
        reqline, headers, body = split_req(raw)
        headers = hdr_set(headers, "Cookie",
                          cookie_merge(hdr_get(headers, "Cookie") or "", pairs))
        return join_req(reqline, headers, body), \
            ["merged %d cookie(s) from fetch" % len(pairs)]

    # -----------------------------------------------------------------------
    # Sending / scoring
    # -----------------------------------------------------------------------
    def _send(self, svc, req_str, interval):
        """One request, rate limited from the moment it goes out."""
        t0 = time.time()
        out = ""
        try:
            rr = self._cb.makeHttpRequest(svc, self._h.stringToBytes(req_str))
            rb = rr.getResponse()
            out = self._h.bytesToString(rb) if rb else ""
        except Exception as ex:
            print("[Access Control] request error: %s" % ex)
        rem = interval - (time.time() - t0)
        if rem > 0:
            time.sleep(rem)
        return out

    def _verdict(self, status, resp, body, base, sim, marker):
        """base is (status, body) of the baseline identity, or None."""
        if status == 0:
            return "NO RESPONSE", "no response - host down, or Burp blocked it"
        head = body[:8000]
        if status in CSRF_FAIL_STATUS and CSRF_FAIL_RE.search(head):
            return "CSRF-FAIL", ("token rejected, NOT an authorization decision"
                                 " - set up this identity's CSRF handling and retest")
        if marker and marker in body:
            return "MARKER FOUND", "response contains the marker"
        if status in (401, 403):
            return "BLOCKED", ""
        if status in (301, 302, 303, 307, 308):
            loc = resp_header(resp, "Location") or ""
            if LOGIN_RE.search(loc):
                return "LOGIN REDIRECT", "Location: " + loc[:90]
            return "DIFFERENT", ("redirect to " + loc[:90]) if loc else "redirect"
        if status == 404:
            return "404", ""
        if status == 429:
            return "RATE LIMITED", "lower req/sec and retest"
        if status >= 500:
            return "5xx", ""
        if base is None:
            if 200 <= status < 300:
                return "200 (no base)", "no baseline identity to compare against"
            return "DIFFERENT", ""
        bstatus, bbody = base
        if status == bstatus:
            if sim >= 0.98:
                return "IDENTICAL", "same status, same body as the baseline"
            if sim >= 0.80:
                return "NEAR-IDENTICAL", "same status, body differs only slightly"
            if sim >= 0.50:
                return "SIMILAR", "same status, roughly half the body matches"
            return "SAME STATUS", "same status as the baseline, different body"
        return "DIFFERENT", "baseline answered %d" % bstatus

    # -----------------------------------------------------------------------
    # Scan
    # -----------------------------------------------------------------------
    def _start(self):
        if self._scan:
            return
        self._commit_identity()
        if not self._targets:
            self._prog.setString("No targets - right-click a request in Burp")
            return
        idents = [i for i in self._ids if i.enabled]
        if not idents:
            self._prog.setString("No identity enabled")
            self._tabs.setSelectedIndex(1)
            return
        try:
            rps = float(self._f_rps.getText().strip() or "5")
        except Exception:
            rps = 5.0
        rps = max(0.2, min(MAX_RPS, rps))
        self._f_rps.setText(str(int(rps)) if rps == int(rps) else str(rps))
        self._save_settings()
        opts = {"strip_cond": self._ck_cond.isSelected(),
                "marker": self._f_marker.getText()}
        self._scan = True
        self._btn_start.setEnabled(False); self._btn_stop.setEnabled(True)
        t = threading.Thread(target=self._worker,
                             args=(list(self._targets), idents, 1.0 / rps, opts))
        t.setDaemon(True); t.start()

    def _stop(self):
        self._scan = False

    def _worker(self, targets, idents, interval, opts):
        try:
            base_ident = None
            for i in idents:
                if i.baseline:
                    base_ident = i
                    break
            # the baseline goes first so every other row has something to score
            order = ([base_ident] if base_ident else []) + \
                    [i for i in idents if i is not base_ident]
            total = 0
            for e in targets:
                for i in order:
                    total += 1
                    if i.csrf_on and (i.csrf_fetch or "").strip():
                        total += 1
            done = 0
            marker = opts["marker"]
            self._store = {}; self._rseq = 1; self._kept = 0
            SwingUtilities.invokeLater(lambda: self._r_model.setRowCount(0))

            for entry in targets:
                if not self._scan:
                    break
                base = None
                base_resp = ""
                for ident in order:
                    if not self._scan:
                        break
                    notes = []
                    try:
                        req, n1 = self._apply_identity(entry["raw"], ident,
                                                       opts["strip_cond"])
                        notes += n1
                        freq = fresp = ""
                        if ident.csrf_on:
                            token, src, freq, fresp, n2 = \
                                self._csrf_prepare(entry, ident, interval)
                            notes += n2
                            if freq:
                                done += 1
                            if fresp and ident.merge_setcookie:
                                req, n3 = self._merge_fetch_cookies(req, fresp)
                                notes += n3
                            if token:
                                req, where = self._inject_token(req, ident, token)
                                notes.append("token from %s -> %s" %
                                             (src, ", ".join(where) or "nowhere"))
                        resp = self._send(entry["svc"], req, interval)
                        done += 1
                        status = status_of(resp)
                        body = body_of(resp)
                        if ident is base_ident:
                            base = (status, body)
                            base_resp = resp
                            verd, note = "BASELINE", ""
                            sim_s, dlen = "-", "-"
                        else:
                            sim = similarity(base[1], body) if base else 0.0
                            verd, note = self._verdict(status, resp, body, base,
                                                       sim, marker)
                            sim_s = "%d" % int(round(sim * 100)) if base else "-"
                            if base:
                                d = len(body) - len(base[1])
                                dlen = ("+%d" % d) if d > 0 else str(d)
                            else:
                                dlen = "-"
                        if note:
                            notes.insert(0, note)
                        rid = self._rseq; self._rseq += 1
                        self._store[rid] = {
                            "req": req, "resp": resp, "base": base_resp,
                            "freq": freq, "fresp": fresp, "svc": entry["svc"],
                            "bytes": self._h.stringToBytes(req)}
                        self._kept += len(resp) + len(fresp)
                        row = [rid, entry["method"], entry["path"], ident.name,
                               status or "-", len(body), dlen, sim_s, verd,
                               "; ".join(notes)]
                        pct = int(done * 100.0 / total) if total else 100
                        SwingUtilities.invokeLater(
                            lambda r=row, p=pct, d=done, tt=total:
                                self._add_result(r, p, "%d / %d" % (d, tt)))
                    except Exception as ex:
                        print("[Access Control] replay error: %s" % ex)
                        done += 1
        except Exception as ex:
            print("[Access Control] worker error: %s" % ex)
        finally:
            self._scan = False
            SwingUtilities.invokeLater(self._done)

    def _add_result(self, row, pct, label):
        self._r_model.addRow(row)
        self._prog.setValue(pct); self._prog.setString(label)
        self._apply_filter()

    def _done(self):
        self._btn_start.setEnabled(True); self._btn_stop.setEnabled(False)
        self._prog.setValue(100)
        hot = csrf = 0
        for i in range(self._r_model.getRowCount()):
            v = str(self._r_model.getValueAt(i, 8))
            if VERDICT_SEV.get(v) == "high":
                hot += 1
            elif v == "CSRF-FAIL":
                csrf += 1
        self._prog.setString("Done - %d to review%s, %.1f MB held"
                             % (hot, (", %d CSRF-FAIL" % csrf) if csrf else "",
                                self._kept / 1048576.0))

    def _apply_filter(self):
        try:
            if self._tg_hits.isSelected():
                self._tg_hits.setBackground(RED)
                self._tg_hits.setForeground(Color.WHITE)
                self._sorter.setRowFilter(RowFilter.regexFilter(
                    "^(IDENTICAL|NEAR-IDENTICAL|MARKER FOUND|SIMILAR|"
                    "200 \\(no base\\)|CSRF-FAIL)$", 8))
            else:
                self._tg_hits.setBackground(BG3)
                self._tg_hits.setForeground(FG)
                self._sorter.setRowFilter(None)
        except Exception as ex:
            print("[Access Control] filter error: %s" % ex)

    # -----------------------------------------------------------------------
    # Viewers / queue management
    # -----------------------------------------------------------------------
    def _show_target(self):
        r = self._t_table.getSelectedRow()
        if 0 <= r < len(self._targets):
            self._v_req.set_text(self._targets[r]["raw"])
            self._v_resp.set_text("")
            self._v_tabs.setSelectedIndex(0)

    def _cur_result(self):
        r = self._r_table.getSelectedRow()
        if r < 0:
            return None
        mr = self._r_table.convertRowIndexToModel(r)
        try:
            return self._store.get(int(str(self._r_model.getValueAt(mr, 0))))
        except Exception:
            return None

    def _show_result(self):
        d = self._cur_result()
        if not d:
            return
        self._v_req.set_text(d["req"])
        self._v_resp.set_text(d["resp"] or "(no response)")
        marker = self._f_marker.getText()
        if marker:
            # jump the response viewer straight to the marker
            self._v_resp.search_for(marker)
        self._v_base.set_text(d["base"] or
                              "(no baseline identity ran for this target)")
        if d["freq"] or d["fresp"]:
            self._v_fetch.set_text((d["freq"] or "") + "\r\n\r\n" + ("-" * 70) +
                                   "\r\n\r\n" + (d["fresp"] or "(no response)"))
        else:
            self._v_fetch.set_text(
                "(CSRF handling was off for this identity, or no token fetch "
                "request was set)")

    def _send_repeater(self):
        d = self._cur_result()
        if not d:
            return
        try:
            svc = d["svc"]
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https",
                                    d["bytes"], "ACL")
        except Exception as ex:
            print("[Access Control] sendToRepeater failed: %s" % ex)

    def _del_target(self):
        r = self._t_table.getSelectedRow()
        if 0 <= r < len(self._targets):
            self._targets.pop(r)
            self._t_model.setRowCount(0)
            for n, e in enumerate(self._targets):
                self._t_model.addRow([n + 1, e["method"], e["host"], e["path"]])

    def _clear_targets(self):
        self._targets = []
        self._t_model.setRowCount(0)

    def _clear_results(self):
        self._r_model.setRowCount(0)
        self._store = {}; self._rseq = 1; self._kept = 0
        for v in (self._v_req, self._v_resp, self._v_base, self._v_fetch):
            v.set_text("")
        self._prog.setValue(0); self._prog.setString("Idle")

    # -----------------------------------------------------------------------
    # ITab / unload
    # -----------------------------------------------------------------------
    def getTabCaption(self):  return "Access Control"
    def getUiComponent(self): return self._root

    def extensionUnloaded(self):
        self._scan = False
        self._save_settings()
        print("[Access Control] Unloaded.")
