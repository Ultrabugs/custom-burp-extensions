# -*- coding: utf-8 -*-
# Reflector v6 - Burp Suite Extension (active reflection tester)
#
# New in v6:
#   * "CRLF recheck". A canary that comes back in a response header - Location
#     above all - means the parameter is written into a header, which is where
#     CRLF injection lives. The "Recheck headers for CRLF" button on the
#     Reflections tab takes every reflection that landed in a header and resends
#     that point with a list of CRLF payloads, each trying to inject a header
#     nothing else uses:
#
#         ...&param=%0d%0aX-CRLF-Test:crlfezwin
#
#     and reports, per point, whether the server grew a REAL new header line
#     from it (confirmed injection, High) or left the %0d%0a encoded inside the
#     Location value (no injection). The list covers %0d%0a, upper-case hex, LF
#     only, CR only, a valid-value prefix, the unicode CR/LF bypass, double URL
#     encoding, and a Set-Cookie injection. The first payload that fires is
#     proof, so it stops there. Results land in the new CRLF tab; click a row
#     for the request/response, or Send to Repeater to drive it by hand.
#   * "Clear everything on new Send" (Queue tab, on by default). Each new "Send
#     to Reflector v6" wipes the queue and every result tab - Reflections, XSS
#     Chars, CRLF and Findings - first, so you start clean without clicking
#     Clear on each one. Turn it off to add several hosts to one queue.
#
# New in v5:
#   * "XSS char recheck". A plain "the canary came back" tells you a parameter
#     is reflected; it does not tell you whether you can break out and run
#     script. So once a scan has found the reflections, the "Recheck reflected
#     with XSS chars" button on the Reflections tab resends every reflected
#     point with a breakout probe - the canary wrapped around the characters
#     that matter for XSS:
#
#         xssezwin'"`<>winezssx
#
#     and reports, per point, which of  '  "  `  <  >  came back
#     RAW (not entity-encoded, not stripped) in the response. These five are
#     the breakout characters - the ones that let you escape the context the
#     value sits in; () ; {} are left out on purpose (they execute or flag
#     template injection, they do not break you out). The alnum
#     xssezwin ... winezssx bookends locate the reflection unambiguously even
#     in noisy HTML; everything between them is read off the wire byte for
#     byte, so a < that reflects as &lt; is correctly called "encoded", not
#     "reflected".
#   * The new XSS Chars tab pairs those surviving characters with the context
#     the value landed in (from v3's classifier) and gives a verdict: e.g.
#     "can inject a tag (< and > both survive)" in HTML text is High, while the
#     same chars encoded is "all special chars filtered". The idea is kxss /
#     Gxss: find reflections first, then prove the breakout.
#
# New in v4:
#   * A host import queues everything the host has. The two filters it used to
#     apply unconditionally - skipping static files, and collapsing an endpoint
#     to one entry per injection surface - are now checkboxes on the Queue tab,
#     both off by default, and the per-invocation cap is 5000 instead of 500.
#     With de-duplication off only byte-identical requests are dropped, so
#     /s?q=1 and /s?q=2 both land in the queue.
#
# New in v3:
#   * "Send whole host(s) from site map to Reflector v6" on the right-click
#     menu. Highlight one or more hosts in the Site map (or any request
#     belonging to them) and every request Burp has already recorded for those
#     hosts is pulled into the queue recursively - no expanding the tree and
#     shift-selecting by hand. Static files with no parameters, and repeats of
#     an endpoint whose injection surface is already queued, are dropped; the
#     console says what was skipped and why.
#   * The queue has its own tab, so the reflections table gets the full window.
#     That tab also lists the injection points parsed out of the selected
#     request, next to its raw text.
#   * Every occurrence of the canary is classified by what it landed *inside*:
#     HTML text, a quoted or unquoted attribute (with the tag@attr it belongs
#     to), a JS string or bare JS code, a template literal, a comment, a JSON
#     key or string value, the host part of a Location header, a Set-Cookie
#     name or value, and so on. The Context column shows the most interesting
#     one as the scan runs - lit up in amber when it is a context you can
#     usually do something with - and the Reflection contexts panel under the
#     table lists every occurrence with the characters that would break out of
#     it. The Snippet column keeps the surrounding text.
#
# New in v2: when a canary reflects inside a JSON response, the same request is
# replayed with the Accept header match-replaced by "Accept: text/html". If the
# endpoint then answers with a text/html content type the reflection becomes
# renderable in a browser, which is the content-type-confusion XSS primitive.
# Those cases land in their own Findings tab.
# Install: Extender > Extensions > Add > Type: Python > Select this file
# Requires: Jython standalone JAR configured in Extender > Options > Python Environment
#
# Right-click request(s) in the Site map / Proxy > Send to Reflector. It injects
# the canary "xssezwin" into each URL/body parameter and the path, one by one,
# sends them (rate-limited to 5 req/s max), and reports which ones reflect the
# canary in the response. Use Send to Repeater to probe a hit manually.
#
# Inject mode (Replace / Append / Both):
#   Replace - the value becomes the canary (?id=xssezwin), the path gets it as a
#             new segment (/api/user -> /api/user/xssezwin). This was v2's only
#             behaviour.
#   Append  - the canary is glued onto the end of what is already there
#             (?id=42xssezwin, /api/user -> /api/userxssezwin), so reflections
#             behind validation, type checks or path routing that reject a bare
#             canary still show up.
#   Both    - every point twice, replace then append (double the requests).
#             Append probes that would duplicate the replace probe (empty/null
#             value, root path) are skipped.
# The Mode column on Reflections and Findings says which probe produced the row.
#
# Reading the Reflections table:
#   Resp CT  - what the response claimed to be (JSON / HTML / JS / XML / ...).
#              The same reflection is a different bug in each of them.
#   Point    - which kind of injection point was used (URL / Body / JSON / Path).
#   In       - where the canary came back: "Body", "Header: Location",
#              "Header: Set-Cookie + Body", and so on.
#
# The All / Body / Headers tabs are three views of the same rows, each
# permanently filtered on that "In" column, with a live count in the tab title.
# A canary that comes back in Location is a redirect / header injection lead,
# not body XSS, and mixing the two into one list is how the header cases get
# lost. The Show / Reflected Only filters apply inside whichever tab is open.
# The Accept: text/html recheck only fires on *body* reflections, since a
# header-only hit is not the content-type-confusion primitive.

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField, JCheckBox,
    JTextArea, JSplitPane, JMenuItem, SwingUtilities, BorderFactory,
    JRadioButton, ButtonGroup, RowFilter, JTabbedPane, JProgressBar, Box,
    JToggleButton, JTree
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.text import DefaultHighlighter
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension
from java.util import ArrayList, Comparator
import threading
import time
import re

CANARY = "xssezwin"
MAX_RPS = 5.0
ACCEPT_PROBE = "text/html"      # what the Accept header is replaced with

# ---------------------------------------------------------------------------
# XSS breakout probe
#
# A reflection is only the first half of the story. Whether it is XSS depends
# on which of the characters you need to break out of the surrounding context
# survive un-encoded. The probe is the canary wrapped around that character
# set, with a second alnum marker on the end:
#
#       xssezwin  <>"'`();{}  winezssx
#       ^prefix    ^chars      ^suffix
#
# The two alnum markers never get HTML-encoded, so they locate the reflection
# exactly; whatever sits between them in the *raw* response is what the server
# actually sent back, so "< came back as &lt;" reads as encoded, not reflected.
# This is the kxss / Gxss idea: find the reflection, then probe the breakout.
# ---------------------------------------------------------------------------
XSS_PREFIX = CANARY               # "xssezwin" - the locator the scan already uses
XSS_SUFFIX = "winezssx"           # trailing locator; distinct, alnum, no overlap
# The five breakout characters, and only those: ' " escape a quoted attribute
# or JS string, ` escapes an ES6 template literal, < > open a tag. () ; {} are
# deliberately left out - they help you *execute* once you are already in a JS
# context, or flag template injection, but they do not break you *out* of the
# context the value landed in, so a survivor here is always directly useful.
XSS_CHARS  = ["'", '"', '`', '<', '>']
XSS_PROBE  = XSS_PREFIX + "".join(XSS_CHARS) + XSS_SUFFIX

# How each breakout character looks once HTML-entity-encoded, so a character
# that came back as its entity is reported as "encoded" rather than "stripped".
XSS_ENTITIES = {
    "'": ("&#39;", "&#x27;", "&apos;"),
    '"': ("&quot;", "&#34;", "&#x22;"),
    '`': ("&#96;", "&#x60;"),
    '<': ("&lt;", "&#60;", "&#x3c;"),
    '>': ("&gt;", "&#62;", "&#x3e;"),
}

# ---------------------------------------------------------------------------
# CRLF / header-injection probe
#
# A canary that comes back in a response header (Location above all) means the
# parameter is written into a header, which is where CRLF injection lives: if
# the server does not strip CR/LF from the value, a  %0d%0a  lets you start a
# brand new header line of your own. The proof is unambiguous - inject a header
# with a name nothing else uses and a unique value, then look for it as a REAL
# header line in the response:
#
#     ...&param=%0d%0aX-CRLF-Test:crlfezwin   ->   X-CRLF-Test: crlfezwin
#
# If CR/LF was honoured the marker appears on its own line; if it was not, the
# literal text "%0d%0a" stays inside the Location value and no new line is born,
# so a line that *starts* with the marker name is the whole test.
#
# Every payload is URL-encoded and space-free on purpose: a raw CR/LF or a
# space injected into a query value would corrupt our own outgoing request line
# (makeHttpRequest sends exactly these bytes), not the server's response. The
# server is what decodes %0d%0a back into CR/LF.
# ---------------------------------------------------------------------------
CRLF_HDR = "X-CRLF-Test"
CRLF_VAL = "crlfezwin"
_CRLF_H  = CRLF_HDR + ":" + CRLF_VAL          # injected header, no space (space breaks the URL)

# (label, value injected into the parameter, header line expected if it worked)
CRLF_PAYLOADS = [
    ("%0d%0a standard",        "%0d%0a" + _CRLF_H,                 CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("%0D%0A upper hex",       "%0D%0A" + _CRLF_H,                 CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("%0a LF only",            "%0a" + _CRLF_H,                    CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("%0d CR only",            "%0d" + _CRLF_H,                    CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("valid value then %0d%0a", "1%0d%0a" + _CRLF_H,               CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("unicode CR/LF bypass",   "%E5%98%8A%E5%98%8D" + _CRLF_H,     CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("double-encoded",         "%250d%250a" + _CRLF_H,             CRLF_HDR.lower() + ":" + CRLF_VAL),
    ("Set-Cookie injection",   "%0d%0aSet-Cookie:" + CRLF_VAL + "=1", "set-cookie:" + CRLF_VAL + "=1"),
]

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

KIND_LABEL = {"url": "URL", "body": "Body", "json": "JSON", "path": "Path"}
MODE_LABEL = {"replace": "Replace", "append": "Append"}



# ---------------------------------------------------------------------------
# Reflection context
#
# "The canary came back" is only half an answer.  What decides whether it is
# exploitable is what it came back *inside*: text between tags, a quoted
# attribute, an unquoted attribute, a JS string, a JSON string, the host part
# of a Location header.  Each of these needs a different character to break
# out of, so each one is reported with the characters that would have to
# survive - which is what you go and test by hand next.
# ---------------------------------------------------------------------------
MAX_CTX = 24        # occurrences classified per response
SNIP = 34           # characters of context either side of the canary


class Ctx(object):
    """One occurrence: what it sits in, what breaks out, how interesting."""
    __slots__ = ("label", "out", "rank", "snip", "pos")

    def __init__(self, label, out, rank, snip="", pos=0):
        self.label = label; self.out = out; self.rank = rank
        self.snip = snip; self.pos = pos


def _js_ctx(seg):
    """String / comment state at the end of seg, which is a run of script
    source ending exactly where the canary starts."""
    i, n, quote = 0, len(seg), None
    while i < n:
        ch = seg[i]
        if quote:
            if ch == "\\":
                i += 2; continue
            if ch == quote:
                quote = None
            i += 1; continue
        if ch in "\"'`":
            quote = ch; i += 1; continue
        if ch == "/" and i + 1 < n:
            if seg[i + 1] == "/":
                j = seg.find("\n", i)
                if j < 0:
                    return Ctx("JS // comment", "a newline, then code", 40)
                i = j + 1; continue
            if seg[i + 1] == "*":
                j = seg.find("*/", i)
                if j < 0:
                    return Ctx("JS /* */ comment", "*/ then code", 40)
                i = j + 2; continue
        i += 1
    if quote == '"':
        return Ctx("JS string, double-quoted", '" (and \\ not escaped)', 90)
    if quote == "'":
        return Ctx("JS string, single-quoted", "' (and \\ not escaped)", 90)
    if quote == "`":
        return Ctx("JS template literal", "` or ${ ... }", 88)
    return Ctx("JS code, not in a string", "already code - ; and newline", 92)


_TAG_RE = re.compile(r"<\s*/?\s*([A-Za-z0-9:_.-]+)")


def _tag_ctx(seg):
    """Attribute state inside an unclosed tag. seg starts at its '<' and ends
    where the canary starts."""
    m = _TAG_RE.match(seg)
    tag = (m.group(1) if m else "?").lower()
    i = m.end() if m else 1
    n = len(seg)
    quote, in_val, attr, name = None, False, "", ""
    while i < n:
        ch = seg[i]
        if quote:
            if ch == quote:
                quote, in_val, attr = None, False, ""
            i += 1; continue
        if ch == "=":
            attr, name = name.strip(), ""
            j = i + 1
            while j < n and seg[j].isspace():
                j += 1
            if j < n and seg[j] in "\"'":
                quote, in_val, i = seg[j], True, j + 1
            else:
                in_val, i = True, j
            continue
        if in_val:
            if ch.isspace() or ch == ">":
                in_val, attr = False, ""
            i += 1; continue
        if ch.isspace():
            name = ""
            i += 1; continue
        name += ch
        i += 1
    where = ("%s@%s" % (tag, attr.lower())) if attr else tag
    if quote == '"':
        return Ctx('HTML attribute, double-quoted (%s)' % where, '" then >', 80)
    if quote == "'":
        return Ctx("HTML attribute, single-quoted (%s)" % where, "' then >", 80)
    if in_val:
        return Ctx("HTML attribute, UNQUOTED (%s)" % where,
                   "a space or > - no quote needed", 95)
    return Ctx("inside <%s>, attribute-name position" % tag, "= or >", 75)


def _html_ctx(body, low, idx):
    c = low.rfind("<!--", 0, idx)
    if c >= 0:
        end = low.find("-->", c)
        if end < 0 or end > idx:
            return Ctx("HTML comment", "--> then <", 55)
    for (tag, rank) in (("script", 0), ("style", 60)):
        t = low.rfind("<" + tag, 0, idx)
        if t < 0:
            continue
        close = low.find("</" + tag, t)
        if close >= 0 and close < idx:
            continue
        gt = low.find(">", t)
        if gt < 0 or gt > idx:
            continue
        if tag == "script":
            return _js_ctx(body[gt + 1:idx])
        return Ctx("<style> block", "</style> or a CSS escape", rank)
    lt, gt = low.rfind("<", 0, idx), low.rfind(">", 0, idx)
    if lt > gt:
        return _tag_ctx(body[lt:idx])
    return Ctx("HTML text, between tags", "< (a tag of your own)", 85)


def _json_ctx(body, idx, n):
    i, inside = 0, False
    while i < idx:
        ch = body[i]
        if inside:
            if ch == "\\":
                i += 2; continue
            if ch == '"':
                inside = False
        elif ch == '"':
            inside = True
        i += 1
    if not inside:
        return Ctx("JSON, outside any string", "unquoted already - read the raw body", 25)
    j = body.find('"', idx + n)
    k = j + 1 if j >= 0 else len(body)
    while k < len(body) and body[k].isspace():
        k += 1
    if k < len(body) and body[k] == ":":
        return Ctx("JSON object key", '" and :', 45)
    return Ctx("JSON string value", '" and \\ (check if \\" is escaped)', 50)


_LOC_RE = re.compile(r"^(?:(?P<scheme>[a-zA-Z][\w+.-]*:)?//(?P<host>[^/?#]*))?"
                     r"(?P<path>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#(?P<frag>.*))?$")


def _header_ctx(line, off, name):
    """off is where the canary starts inside the header line."""
    low = name.lower()
    vstart = line.find(":") + 1
    val = line[vstart:].lstrip()
    voff = off - (vstart + (len(line[vstart:]) - len(val)))
    if low == "location":
        m = _LOC_RE.match(val)
        if m:
            for (grp, label, out, rank) in (
                    ("host", "Location host - open-redirect position",
                     "nothing: the whole host is yours", 70),
                    ("query", "Location query value", "& or # (or a whole new URL)", 40),
                    ("path", "Location path", "a path segment or ?", 42),
                    ("frag", "Location fragment", "client-side only", 30)):
                sp = m.start(grp)
                if sp >= 0 and sp <= voff < m.end(grp):
                    return Ctx(label, out, rank)
        return Ctx("Location header", "CR/LF for header injection", 45)
    if low == "set-cookie":
        if voff <= val.find("="):
            return Ctx("Set-Cookie name", "= and ;", 40)
        return Ctx("Set-Cookie value", "; to add attributes", 35)
    if low in ("content-disposition", "content-type", "content-security-policy",
               "access-control-allow-origin", "refresh", "link", "www-authenticate"):
        return Ctx("%s header" % name, "depends on the header grammar", 50)
    return Ctx("%s header value" % name, "CR/LF for header injection", 30)


def _snippet(text, idx, n):
    """The canary marked inside its surroundings, so the exact occurrence is
    obvious even when the window holds more than one of them."""
    s = max(0, idx - SNIP)
    e = min(len(text), idx + n + SNIP)
    def clean(t):
        return display_text(t).replace("\n", " ").replace("\t", " ")
    return (("..." if s > 0 else "")
            + clean(text[s:idx]) + ">>>" + clean(text[idx:idx + n]) + "<<<"
            + clean(text[idx + n:e]) + ("..." if e < len(text) else ""))


def reflect_contexts(resp, ct, canary):
    """Every place the canary came back, classified. Headers first, then the
    body, capped at MAX_CTX so a page that echoes it 500 times cannot stall
    the scan."""
    out = []
    if not resp:
        return out
    head, sep, body = split_head_body(decode_message(resp))
    needle = canary.lower()

    hl = head.replace("\r\n", "\n").split("\n")
    base = 0
    for (i, line) in enumerate(hl):
        low = line.lower()
        at = low.find(needle)
        while at >= 0 and len(out) < MAX_CTX:
            if i == 0:
                c = Ctx("HTTP status line", "CR/LF", 45)
            else:
                nm = line.split(":", 1)[0].strip()
                c = _header_ctx(line, at, nm or "?")
            c.snip = _snippet(line, at, len(canary))
            c.pos = base + at
            out.append(c)
            at = low.find(needle, at + len(needle))
        base += len(line) + 1

    low_b = body.lower()
    kind = ct_label(ct)
    if not kind or kind == "-":
        st = body.lstrip()[:1]
        kind = "HTML" if st == "<" else ("JSON" if st in "{[" else "Text")
    at = low_b.find(needle)
    while at >= 0 and len(out) < MAX_CTX:
        if kind in ("HTML", "XML"):
            c = _html_ctx(body, low_b, at)
        elif kind == "JSON":
            c = _json_ctx(body, at, len(canary))
        elif kind == "JS":
            c = _js_ctx(body[:at])
        elif kind == "CSV":
            c = Ctx("CSV field", "a quote or separator", 25)
        else:
            c = Ctx("%s body (plain)" % kind, "nothing parses it - low value", 20)
        c.snip = _snippet(body, at, len(canary))
        c.pos = at
        out.append(c)
        at = low_b.find(needle, at + len(needle))
    return out


def context_summary(ctxs):
    """(headline label, snippet of that occurrence) for the results table."""
    if not ctxs:
        return "", ""
    best = ctxs[0]
    for c in ctxs:
        if c.rank > best.rank:
            best = c
    labels = []
    for c in ctxs:
        if c.label not in labels:
            labels.append(c.label)
    extra = len(labels) - 1
    head = best.label + ("   (+%d other context%s)" % (extra, "" if extra == 1 else "s")
                         if extra else "")
    return head, best.snip


def context_detail(ctxs, cnt):
    """The per-occurrence breakdown shown under the results table."""
    if not ctxs:
        return "(the canary did not come back in this response)"
    lines = ["%d reflection(s) classified%s:" %
             (len(ctxs), "  (capped at %d)" % MAX_CTX
              if cnt > len(ctxs) else "")]
    for (i, c) in enumerate(ctxs):
        lines.append("")
        lines.append("  [%d] %s" % (i + 1, c.label))
        lines.append("       breaks out with: %s" % c.out)
        lines.append("       %s" % c.snip)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# XSS breakout analysis
#
# After the probe comes back, work out which breakout characters survived. The
# alnum prefix/suffix bracket every reflected copy; the text between them is
# read straight off the wire, so a character is "reflected" only when it is
# present literally AND unescaped, "escaped" when a quote came back only as \"
# \' or \` (a backslash in front neutralises it inside a JS string / JSON, so
# it cannot break out), "encoded" when its HTML entity is there instead, and
# "stripped" when none of those is. Only ' " ` can be backslash-escaped; < and
# > are never escaped that way in HTML, so a raw copy of them always counts.
# ---------------------------------------------------------------------------
def xss_windows(decoded, cap=MAX_CTX):
    """Every reflected copy of the probe as (prefix_pos, probe_len, inner_text).

    inner_text is what sits between the two alnum markers. When the suffix is
    missing - the server mangled or truncated the tail - it falls back to a
    fixed span so a reflection is still reported, just less precisely."""
    out = []
    if not decoded:
        return out
    low = decoded.lower()
    pre, suf = XSS_PREFIX.lower(), XSS_SUFFIX.lower()
    at = low.find(pre)
    while at >= 0 and len(out) < cap:
        start = at + len(pre)
        end = low.find(suf, start)
        if 0 <= end and (end - start) <= 120:
            probe_len = (end + len(suf)) - at
            inner = decoded[start:end]
        else:
            end = min(len(decoded), start + 60)
            probe_len = end - at
            inner = decoded[start:end]
        out.append((at, probe_len, inner))
        nxt = low.find(pre, start)
        at = nxt
    return out


# Only these are escapable with a backslash; < and > are not, in HTML.
_XSS_ESCAPABLE = ("'", '"', '`')


def _is_unescaped(text, idx):
    """True when the character at idx is preceded by an even number (0, 2, 4...)
    of consecutive backslashes - i.e. it is NOT backslash-escaped. An odd run
    (\\" , \\\\\\" ...) means the final backslash escapes the character."""
    k = 0
    j = idx - 1
    while j >= 0 and text[j] == "\\":
        k += 1
        j -= 1
    return (k % 2) == 0


def _char_states(text, ch):
    """(has_unescaped, has_escaped) for ch inside text. For a quote character a
    backslash-escaped copy (\\" \\' \\`) is a survivor only if the backslash is
    itself escaped; otherwise it is reported as escaped, not reflected, because
    it cannot break out of a JS string / JSON. For < and > every raw copy is a
    real survivor - a backslash in front means nothing in HTML."""
    raw = esc = False
    i = text.find(ch)
    while i >= 0:
        if ch in _XSS_ESCAPABLE and not _is_unescaped(text, i):
            esc = True
        else:
            raw = True
        i = text.find(ch, i + 1)
    return (raw, esc)


def analyze_xss_chars(decoded):
    """Which breakout characters survived across every reflected copy, or None
    if the probe did not come back at all (its value was rejected / filtered).

    A quote that came back only backslash-escaped (\\") lands in "escaped", not
    "reflected": it looks like it is there but cannot break out, so it never
    lights the row green or drives a High verdict."""
    wins = xss_windows(decoded)
    if not wins:
        return None
    inners = [w for (_p, _l, w) in wins]
    joined_low = "".join(inners).lower()
    reflected, encoded, stripped, escaped = [], [], [], []
    for ch in XSS_CHARS:
        raw = esc = False
        for inner in inners:
            r, e = _char_states(inner, ch)
            raw = raw or r
            esc = esc or e
        if raw:
            reflected.append(ch)
        elif esc:
            escaped.append(ch)
        elif any(e in joined_low for e in XSS_ENTITIES.get(ch, ())):
            encoded.append(ch)
        else:
            stripped.append(ch)
    at, plen, _inner = wins[0]
    return {"reflected": reflected, "encoded": encoded, "stripped": stripped,
            "escaped": escaped, "count": len(wins),
            "snippet": _snippet(decoded, at, plen)}


def xss_verdict(ctxs, reflected, escaped=()):
    """Marry the surviving characters to where the value landed, and name the
    outcome. Returns (verdict text, severity) where severity is High / Medium /
    low and drives the row colour - the same ranking the Context column uses to
    pick the one occurrence worth leading with. `escaped` holds quotes that came
    back only backslash-escaped, so the verdict can say "escaped" (the backslash
    neutralised it) rather than the vaguer "filtered"."""
    rc = set(reflected)
    ec = set(escaped)
    best = None
    for c in (ctxs or []):
        if best is None or c.rank > best.rank:
            best = c
    low = (best.label if best else "").lower()
    both_angles = ('<' in rc and '>' in rc)

    if "unquoted" in low:
        if '>' in rc:
            return ("unquoted attribute, > survives - add your own handler/tag", "High")
        return ("unquoted attribute but > is filtered", "Medium")
    if "html text" in low or "html comment" in low or "between tags" in low:
        if both_angles:
            return ("can inject a tag - < and > both survive", "High")
        if '<' in rc:
            return ("< survives but > is filtered - partial", "Medium")
        return ("angle brackets filtered", "low")
    if "<style>" in low:
        return ("inside <style> - CSS injection if < / > survive", "Medium"
                if both_angles else "low")
    if "js string, double-quoted" in low:
        if '"' in rc:
            return ('breaks out of the JS string - " survives', "High")
        if '"' in ec:
            return ('" came back backslash-escaped (\\") - cannot break out', "low")
        return ('" filtered inside the JS string', "low")
    if "js string, single-quoted" in low:
        if "'" in rc:
            return ("breaks out of the JS string - ' survives", "High")
        if "'" in ec:
            return ("' came back backslash-escaped (\\') - cannot break out", "low")
        return ("' filtered inside the JS string", "low")
    if "template literal" in low:
        if '`' in rc:
            return ("breaks out of the template literal - ` survives", "High")
        if '`' in ec:
            return ("` came back backslash-escaped (\\`) - cannot break out", "low")
        return ("backtick filtered inside the template literal", "low")
    if "js code" in low:
        return ("already in JS code - the reflection is script", "High")
    if "attribute, double-quoted" in low:
        if '"' in rc:
            return ('breaks out of the attribute - " survives', "High")
        if '"' in ec:
            return ('" came back backslash-escaped (\\") - cannot leave the attribute', "low")
        return ('" filtered - cannot leave the attribute', "low")
    if "attribute, single-quoted" in low:
        if "'" in rc:
            return ("breaks out of the attribute - ' survives", "High")
        if "'" in ec:
            return ("' came back backslash-escaped (\\') - cannot leave the attribute", "low")
        return ("' filtered - cannot leave the attribute", "low")
    if "attribute-name position" in low:
        return ("attribute-name position, > survives - add a handler", "High") \
            if '>' in rc else ("attribute-name position, > filtered", "Medium")
    if "json" in low:
        if '"' in rc:
            return ('JSON string - " survives, check it is served as HTML', "Medium")
        if '"' in ec:
            return ('" came back backslash-escaped (\\") inside the JSON string', "low")
        return ('" escaped inside the JSON string', "low")
    if "location" in low:
        return ("Location header reflection - redirect / CRLF, not body XSS",
                "Medium")
    if "header" in low or "set-cookie" in low or "status line" in low:
        return ("header reflection - CRLF / header injection, not body XSS",
                "Medium" if rc else "low")

    # No usable context label: judge on the raw survivors alone.
    if both_angles:
        return ("< and > survive - likely tag injection", "High")
    if rc:
        return ("some characters survive: %s" % " ".join(sorted(rc)), "Medium")
    return ("all breakout characters filtered", "low")


# ---------------------------------------------------------------------------
# CRLF / header-injection detection
#
# The question is never "did my value come back" - it is "did my CR/LF spawn a
# new header line". So the response head is split on CR, LF and CRLF, and a hit
# is a line that *starts* with the marker we injected. A value that merely
# reflected with the %0d%0a still URL-encoded stays glued inside the Location
# line (which starts with "location:"), so it can never satisfy that test - no
# false positive from plain reflection.
# ---------------------------------------------------------------------------
def _resp_head(resp_raw):
    """The response's header block - headers are never gzip/chunk encoded, so
    this needs no decoding."""
    if not resp_raw:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        i = resp_raw.find(sep)
        if i >= 0:
            return resp_raw[:i]
    return resp_raw


def detect_crlf(resp_raw, expected_line):
    """(hit, evidence line). hit is True when a header line begins with the
    header we tried to inject - i.e. the server turned our CR/LF into a real
    line break. Spaces are ignored in the match so a server that reformats
    "X-CRLF-Test:v" to "X-CRLF-Test: v" is still caught; the marker values
    carry no spaces of their own, so this cannot widen the match wrongly."""
    head = _resp_head(resp_raw)
    if not head:
        return (False, "")
    lines = head.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    exp = expected_line.lower().replace(" ", "")
    for line in lines[1:]:                      # skip the status line
        s = line.strip()
        if s.lower().replace(" ", "").startswith(exp):
            return (True, s)
    return (False, "")


def header_line_with(resp_raw, marker):
    """The first response header line that contains marker, trimmed - used to
    show where the value landed when no injection fired (still encoded)."""
    head = _resp_head(resp_raw)
    low = marker.lower()
    for line in head.replace("\r\n", "\n").replace("\r", "\n").split("\n")[1:]:
        if low in line.lower():
            s = line.strip()
            return s if len(s) <= 220 else s[:220] + " ..."
    return ""


# ---------------------------------------------------------------------------
# Site map import
#
# Right-clicking a host in the Site map tree and picking the recursive item
# pulls every request Burp has already recorded for that host into the queue,
# instead of having to expand the tree and shift-select requests by hand.
#
# A Site map tree selection hands back one entry per selected node. That entry
# has a URL but usually no request bytes, so its URL has to be read with
# getUrl() - analyzeRequest() has nothing to work with and comes back empty,
# which is what made an earlier attempt at this silently find no hosts. The
# node's own URL is then the prefix for getSiteMap(), which returns the whole
# subtree: the host for a host node, the folder for a folder node. Default
# ports are stripped first, because Burp renders site map URLs without them and
# older builds will not match a prefix that spells one out. This is the same
# route GAP takes, and it is the one that works.
# ---------------------------------------------------------------------------
MAX_IMPORT = 5000       # per invocation; a stop so one host cannot hang Burp
CTX_SITE_MAP_TREE = 4   # IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE

# Skipped on import when the URL carries no parameters at all - a static file
# with nothing to inject into is just wasted requests. A parameterised one
# (/thumb.png?src=...) is kept whatever its extension says.
STATIC_EXT = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".tiff", ".webp", ".avif", ".svg", ".ico", ".cur", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".m4a", ".webm", ".ogg", ".wav",
    ".avi", ".mov", ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".tar", ".exe", ".dmg", ".msi", ".apk", ".dll", ".class", ".jar",
)


def strip_default_port(u):
    """Burp renders site map URLs without the default port, and older builds'
    getSiteMap() will not match a prefix that spells it out - which is why a
    prefix built from analyzeRequest().getUrl() can come back with nothing."""
    for scheme, port in (("https://", ":443"), ("http://", ":80")):
        if u[:len(scheme)].lower() == scheme:
            rest = u[len(scheme):]
            slash = rest.find("/")
            auth = rest if slash < 0 else rest[:slash]
            tail = "" if slash < 0 else rest[slash:]
            if auth.endswith(port):
                auth = auth[:-len(port)]
            return scheme + auth + tail
    return u


def url_authority(u):
    i = u.find("://")
    if i < 0:
        return ""
    rest = u[i + 3:]
    j = rest.find("/")
    return (rest if j < 0 else rest[:j]).lower()


def find_jtree(comp, depth=0):
    """The JTree at or under comp."""
    if comp is None or depth > 6:
        return None
    if isinstance(comp, JTree):
        return comp
    try:
        kids = comp.getComponents()
    except Exception:
        return None
    for ch in kids:
        t = find_jtree(ch, depth + 1)
        if t is not None:
            return t
    return None


def jtree_from_event(ev):
    """The site map tree behind a context menu invocation.

    Burp gives extensions no way to ask what is selected in the Site map tree -
    getSelectedMessages() comes back empty for a host or folder node, which is
    exactly the case worth having. What it does give is the input event the
    menu came from, and for a click in the tree that event belongs to the
    JTree itself (or to something inside it), so the selection can be read off
    the component directly."""
    if ev is None:
        return None
    comp = None
    try:
        comp = ev.getComponent()
    except Exception:
        pass
    if comp is None:
        try:
            comp = ev.getSource()
        except Exception:
            return None
    c = comp
    for _ in range(8):
        if c is None:
            break
        if isinstance(c, JTree):
            return c
        try:
            c = c.getParent()
        except Exception:
            break
    return find_jtree(comp)


def node_label(node):
    try:
        return node.toString() or ""
    except Exception:
        try:
            return str(node)
        except Exception:
            return ""


HOSTISH_RE = re.compile(r"^[A-Za-z0-9._-]+(:\d+)?$")


def tree_selection_labels(tree):
    """The node labels of every selected branch, root first."""
    out = []
    try:
        paths = tree.getSelectionPaths()
    except Exception:
        return out
    for tp in (paths or []):
        try:
            out.append([node_label(n) for n in tp.getPath()])
        except Exception:
            continue
    return out


def tree_prefixes(tree):
    """A getSiteMap() prefix for every selected branch of the Site map tree.

    The node labels rebuild the URL: the host node renders as
    "https://example.com[:port]" and each child is one path segment, so a host
    selection gives "https://example.com/" and a folder selection gives
    "https://example.com/api/". Only the trailing-slash form is used - trimming
    it would turn "https://example.com" into a prefix that also matches
    example.com.evil.net, and "/api" into one that also matches /apiv2."""
    out = []
    for labels in tree_selection_labels(tree):
        pref = None
        for i in range(len(labels)):
            lbl = (labels[i] or "").strip()
            if "://" in lbl:
                rest = [x.strip("/") for x in labels[i + 1:] if (x or "").strip("/")]
                pref = lbl.rstrip("/")
                if rest:
                    pref += "/" + "/".join(rest)
                break
        if pref:
            if not pref.endswith("/"):
                pref += "/"
            if pref not in out:
                out.append(pref)
            continue
        # Some builds label the host node without the scheme. Both schemes are
        # tried; the wrong one simply matches nothing in the site map.
        rest = [(x or "").strip("/") for x in labels[1:]]
        rest = [x for x in rest if x]
        if not rest or not HOSTISH_RE.match(rest[0]):
            continue
        tail = ("/" + "/".join(rest[1:])) if len(rest) > 1 else ""
        for sch in ("https://", "http://"):
            p = sch + rest[0] + tail
            if not p.endswith("/"):
                p += "/"
            if p not in out:
                out.append(p)
    return out


def drop_nested(prefixes):
    """Keep the broadest of any overlapping prefixes - scanning both
    https://x/ and https://x/api/ is the same work twice."""
    out = []
    for p in prefixes:
        if any(p != q and p.startswith(q) for q in prefixes):
            continue
        if p not in out:
            out.append(p)
    return out


def url_host_root(url_str):
    """https://x.com:8443/a/b?q=1  ->  https://x.com:8443/"""
    i = url_str.find("://")
    if i < 0:
        return url_str
    j = url_str.find("/", i + 3)
    return url_str if j < 0 else url_str[:j + 1]


def is_static_url(url_str, has_body):
    """A static asset with no parameters of any kind."""
    if "?" in url_str or has_body:
        return False
    base = url_str.split("#", 1)[0].lower()
    for ext in STATIC_EXT:
        if base.endswith(ext):
            return True
    return False


def reflect_location(head, hcnt, bcnt):
    """Where the canary came back: "Body", "Header: Location", or both. The
    header names matter - Location, Set-Cookie and Content-Disposition each
    mean something different from a body reflection."""
    if not (hcnt or bcnt):
        return ""
    parts = []
    if hcnt:
        names = []
        for (i, line) in enumerate(head.replace("\r\n", "\n").split("\n")):
            if CANARY not in line.lower():
                continue
            nm = "(status line)" if i == 0 else line.split(":", 1)[0].strip()
            if nm and nm not in names:
                names.append(nm)
        parts.append(("Header: " + ", ".join(names)) if names else "Header")
    if bcnt:
        parts.append("Body")
    return " + ".join(parts)


def ct_label(ct):
    """A short tag for the response's Content-Type - what the reflection is
    sitting inside, which is what decides whether it is exploitable."""
    c = (ct or "").split(";")[0].strip().lower()
    if not c:
        return "-"
    if "json" in c:
        return "JSON"
    if "html" in c:
        return "HTML"
    if "javascript" in c or "ecmascript" in c:
        return "JS"
    if "xml" in c:
        return "XML"
    if "csv" in c:
        return "CSV"
    if "x-www-form-urlencoded" in c:
        return "Form"
    if c.startswith("image/"):
        return "Image"
    if c.startswith("text/"):
        return "Text"
    return c

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
# JSON or HTML, so the pretty printer had nothing to format and the canary
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
NOT_RETAINED = ("(response not retained - this probe did not reflect the canary)\n\n"
                "Keeping every probe's response meant tens of MB of strings sitting "
                "in Burp's heap on a page with many injection points. Tick \"Keep all "
                "responses\" before scanning to hold on to all of them, or use Send "
                "to Repeater to fetch this one again.")
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
                    "Nothing is cut: use Find to reach the canary. ]\n\n"
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
# Models / renderers / listeners
# ---------------------------------------------------------------------------
class QueueModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, ["#", "Method", "Host", "Path", "Points"], 0)
    def isCellEditable(self, r, c): return False

class PointModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, ["Point", "Parameter", "Current value"], 0)
    def isCellEditable(self, r, c): return False

class ResultModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Method", "Resp CT", "Request", "Point", "Parameter",
             "Mode", "Reflected", "In", "Count", "Context", "Snippet"], 0)
    def isCellEditable(self, r, c): return False

class FindingsModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Severity", "Request", "Where", "Parameter", "Mode",
             "JSON type", "With Accept: text/html", "Canary", "Notes"], 0)
    def isCellEditable(self, r, c): return False

class FindingsRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr  = table.convertRowIndexToModel(row)
        sev = str(table.getModel().getValueAt(mr, 1) or "")
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif sev == "High":
            c.setBackground(Color(70, 35, 35)); c.setForeground(Color(255, 120, 120))
        elif sev == "Medium":
            c.setBackground(Color(70, 60, 30)); c.setForeground(YELLOW)
        else:
            c.setBackground(BG2); c.setForeground(FG)
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c

class FindingRowSel(ListSelectionListener):
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._f_table.getSelectedRow()
            if r >= 0:
                self._e._show_finding(r)

class XssModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Risk", "Method", "Request", "Point", "Parameter", "Mode",
             "Resp CT", "Context", "Reflected chars", "Filtered", "Verdict",
             "Snippet"], 0)
    def isCellEditable(self, r, c): return False

class XssRenderer(DefaultTableCellRenderer):
    """High in red, Medium in amber, everything else dim - and the surviving
    characters cell lit green whenever any character got through."""
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr  = table.convertRowIndexToModel(row)
        sev = str(table.getModel().getValueAt(mr, 1) or "")
        refl = str(table.getModel().getValueAt(mr, 9) or "")
        got = bool(refl) and refl != "(none)"
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif sev == "High":
            c.setBackground(Color(70, 35, 35)); c.setForeground(Color(255, 120, 120))
        elif sev == "Medium":
            c.setBackground(Color(70, 60, 30)); c.setForeground(YELLOW)
        else:
            c.setBackground(BG2); c.setForeground(FG_DIM)
        if not sel and col == 9 and got:
            c.setForeground(Color(255, 190, 90))
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c

class XssRowSel(ListSelectionListener):
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._x_table.getSelectedRow()
            if r >= 0:
                self._e._show_xss(r)

class XssNonHeaderFilter(RowFilter):
    """Hides XSS rows whose probe reflected ONLY in a response header - those
    are CRLF / redirect leads (use the CRLF tab), not body XSS. Header-ness is
    looked up by row id in the panel's _xheader map, computed when the row was
    built, so it does not depend on scraping the visible text."""
    def __init__(self, panel):
        self._panel = panel
    def include(self, entry):
        try:
            xid = int(str(entry.getValue(0)))
        except Exception:
            return True
        return not self._panel._xheader.get(xid, False)

class CrlfModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Risk", "Method", "Request", "Point", "Parameter", "Mode",
             "Reflected in", "Working payload", "Injected line", "Verdict",
             "Snippet"], 0)
    def isCellEditable(self, r, c): return False

class CrlfRenderer(DefaultTableCellRenderer):
    """High (injection confirmed) in red, everything else dim; the working
    payload cell lit green on a confirmed hit."""
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr  = table.convertRowIndexToModel(row)
        sev = str(table.getModel().getValueAt(mr, 1) or "")
        payload = str(table.getModel().getValueAt(mr, 8) or "")
        hit = bool(payload) and payload != "-"
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif sev == "High":
            c.setBackground(Color(70, 35, 35)); c.setForeground(Color(255, 120, 120))
        elif sev == "Medium":
            c.setBackground(Color(70, 60, 30)); c.setForeground(YELLOW)
        else:
            c.setBackground(BG2); c.setForeground(FG_DIM)
        if not sel and col == 8 and hit:
            c.setForeground(Color(255, 190, 90))
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c

class CrlfRowSel(ListSelectionListener):
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._c_table.getSelectedRow()
            if r >= 0:
                self._e._show_crlf(r)

class NumComparator(Comparator):
    def compare(self, a, b):
        return cmp(self._f(a), self._f(b))
    def _f(self, v):
        try:
            return float(str(v).strip())
        except Exception:
            return float("-inf")

# Contexts you can usually do something with - the Context cell is drawn in
# warning colours for these so they stand out while the scan is still running.
HOT_CTX = ("UNQUOTED", "JS code", "JS string", "template literal",
           "HTML text", "open-redirect")


class ResultRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr = table.convertRowIndexToModel(row)
        refl = str(table.getModel().getValueAt(mr, 7) or "")
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif refl == "YES":
            c.setBackground(Color(40, 60, 40)); c.setForeground(GREEN)
            if col == 10:
                ctx = str(table.getModel().getValueAt(mr, 10) or "")
                if any(k in ctx for k in HOT_CTX):
                    c.setBackground(Color(72, 48, 24))
                    c.setForeground(Color(255, 190, 90))
        else:
            c.setBackground(BG2); c.setForeground(FG_DIM)
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c

class QueueRowSel(ListSelectionListener):
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._q_table.getSelectedRow()
            if r >= 0:
                self._e._show_queue(r)

class ResultRowSel(ListSelectionListener):
    """One per location tab: the tabs are separate JTables over one model."""
    def __init__(self, ext, table):
        self._e = ext; self._t = table
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._t.getSelectedRow()
            if r >= 0:
                self._e._show_result(self._t, r)

# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb    = callbacks
        self._h     = callbacks.getHelpers()
        self._queue = []        # dicts: {raw, svc, method, host, path, points}
        self._rstored = {}      # result# -> dict(req, resp|None, svc, bytes, detail)
        self._kept = 0          # bytes of response text held for the viewer
        self._rseq  = 1
        self._n_all = self._n_body = self._n_hdr = 0   # per-location tab counts
        self._fstored = {}      # finding# -> (req_str, resp_str, svc, bytes)
        self._fseq  = 1
        self._xstored = {}      # xss#    -> (req_str, resp_str, svc, bytes)
        self._xheader = {}      # xss#    -> True if the probe reflected only in a header
        self._xseq  = 1
        self._cstored = {}      # crlf#   -> (req_str, resp_str, svc, bytes)
        self._cseq  = 1
        self._scan  = False
        self._xscan = False     # XSS char recheck in progress
        self._cscan = False     # CRLF recheck in progress
        self._lock  = threading.Lock()

        callbacks.setExtensionName("Reflector v6")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        if SwingUtilities.isEventDispatchThread():
            self._build()
        else:
            SwingUtilities.invokeAndWait(lambda: self._build())
        print("[Reflector v6] Loaded — right-click requests in Site map > Send to Reflector v6.")

    # -----------------------------------------------------------------------
    # UI
    # -----------------------------------------------------------------------
    def _build(self):
        scan_panel = JPanel(BorderLayout(6, 6))
        scan_panel.setBackground(BG)
        scan_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # Controls - two rows inside a BorderLayout. A single FlowLayout here
        # is given one row's height by BorderLayout.NORTH, so anything that
        # wrapped was drawn over the panel below instead of onto a second row.
        def ctl_row():
            r = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))
            r.setBackground(BG)
            return r

        row1, row2 = ctl_row(), ctl_row()
        bar = JPanel(BorderLayout())
        bar.setBackground(BG)
        bar.add(row1, BorderLayout.NORTH)
        bar.add(row2, BorderLayout.SOUTH)

        row1.add(mk_lbl("Canary:", 12, True))
        row1.add(mk_lbl(CANARY, 12, color=ACCENT))
        row1.add(Box.createHorizontalStrut(8))
        row1.add(mk_lbl("Inject:", 12, True))
        self._rb_replace = mk_radio("Replace", True)
        self._rb_append  = mk_radio("Append")
        self._rb_both    = mk_radio("Both")
        self._rb_replace.setToolTipText(
            "Replace the parameter's value with the canary (?id=xssezwin) and "
            "test the path by adding the canary as a new segment (/api/user/xssezwin).")
        self._rb_append.setToolTipText(
            "Append the canary to the end of what is already there "
            "(?id=42xssezwin) and glue it onto the last path segment "
            "(/api/user -> /api/userxssezwin). Finds reflections behind "
            "validation, type checks or routing that a bare canary fails.")
        self._rb_both.setToolTipText(
            "Run every injection point twice, replace then append - double the "
            "requests. Append probes that would duplicate the replace probe "
            "(empty or null original value) are skipped.")
        g_mode = ButtonGroup()
        for rb in (self._rb_replace, self._rb_append, self._rb_both):
            g_mode.add(rb); row1.add(rb)
        row1.add(Box.createHorizontalStrut(8))
        self._ck_keep = mk_check("Keep all responses", False)
        self._ck_keep.setToolTipText(
            "Off (recommended): only responses that reflected the canary are held "
            "for the viewer - findings are always kept. On: every probe's response "
            "is retained, which is what made Burp sluggish on big scans.")
        row1.add(self._ck_keep)
        self._ck_accept = mk_check("Accept: text/html recheck", True)
        self._ck_accept.setToolTipText(
            "When the canary reflects inside a JSON response, replay the same "
            "request with the Accept header replaced by \"Accept: %s\". "
            "If the endpoint answers with an HTML content type the reflection "
            "becomes renderable - that goes in the Findings tab. Costs one "
            "extra request per JSON reflection." % ACCEPT_PROBE)
        row1.add(self._ck_accept)
        row1.add(Box.createHorizontalStrut(8))
        row1.add(mk_lbl("Req/sec (max %d):" % int(MAX_RPS)))
        self._f_rps = mk_field("5", 4)
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
        self._prog.setPreferredSize(Dimension(260, 22))
        self._prog.setBackground(BG3); self._prog.setForeground(ACCENT)
        row2.add(self._prog)
        scan_panel.add(bar, BorderLayout.NORTH)

        # Results - the whole width now that the queue has its own tab
        r_top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); r_top.setBackground(BG)
        r_top.add(mk_lbl("Show:"))
        self._rb_all = mk_radio("All", True); self._rb_get = mk_radio("GET"); self._rb_write = mk_radio("POST/PUT/PATCH")
        mg = ButtonGroup()
        for rb in (self._rb_all, self._rb_get, self._rb_write):
            mg.add(rb); rb.addActionListener(lambda e: self._apply_filters()); r_top.add(rb)
        self._tg_refl = JToggleButton("Reflected Only")
        self._tg_refl.setBackground(BG3); self._tg_refl.setForeground(FG)
        self._tg_refl.setFocusPainted(False); self._tg_refl.setBorderPainted(False)
        self._tg_refl.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._tg_refl.addActionListener(lambda e: self._toggle_refl())
        r_top.add(self._tg_refl)
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_repeater())
        r_top.add(b_rep)
        b_rc = mk_btn("Clear Results", BG3, FG); b_rc.addActionListener(lambda e: self._clear_r())
        r_top.add(b_rc)
        r_top.add(Box.createHorizontalStrut(8))
        self._btn_xss = mk_btn("Recheck reflected with XSS chars", YELLOW, BG)
        self._btn_xss.setToolTipText(
            "Resend every reflected point with the breakout probe %s and report, "
            "per point, which of  %s  came back raw (not entity-encoded). "
            "Results land in the XSS Chars tab. Honours the Req/sec limit above."
            % (XSS_PROBE, " ".join(XSS_CHARS)))
        self._btn_xss.addActionListener(lambda e: self._xss_recheck_start())
        r_top.add(self._btn_xss)
        self._btn_crlf = mk_btn("Recheck headers for CRLF", YELLOW, BG)
        self._btn_crlf.setToolTipText(
            "For every reflection that landed in a response header (Location, "
            "Set-Cookie, ...), resend the point with %d CRLF payloads that each "
            "try to inject a '%s' header, and report which - if any - the server "
            "honours. Results land in the CRLF tab. Honours the Req/sec limit."
            % (len(CRLF_PAYLOADS), CRLF_HDR))
        self._btn_crlf.addActionListener(lambda e: self._crlf_recheck_start())
        r_top.add(self._btn_crlf)

        self._r_model = ResultModel()
        self._views = []        # {t: JTable, s: sorter, loc: regex or None}
        self._rt_tabs = JTabbedPane()
        self._rt_tabs.setBackground(BG); self._rt_tabs.setForeground(FG)
        self._rt_tabs.setFont(Font("Segoe UI", Font.BOLD, 11))
        for (title, card, loc) in (
                ("  All  ", "Every probe", None),
                ("  Body  ", "Canary in the response body", "Body"),
                ("  Headers  ", "Canary in a response header (Location, "
                                "Set-Cookie, ...)", "Header:")):
            self._rt_tabs.addTab(title, mk_card(card, self._mk_result_view(loc)))
        self._rt_tabs.setToolTipTextAt(1,
            "Reflections inside the body - the XSS / injection primitive, read "
            "together with the Resp CT column.")
        self._rt_tabs.setToolTipTextAt(2,
            "Reflections in a response header instead. A canary in Location is "
            "an open redirect / header injection lead, not body XSS.")
        r_wrap = JPanel(BorderLayout()); r_wrap.setBackground(BG)
        r_wrap.add(r_top, BorderLayout.NORTH)
        r_wrap.add(self._rt_tabs, BorderLayout.CENTER)

        # Every occurrence of the selected row, classified
        self._ctx_area = JTextArea()
        self._ctx_area.setBackground(BG2); self._ctx_area.setForeground(FG)
        self._ctx_area.setEditable(False); self._ctx_area.setLineWrap(False)
        self._ctx_area.setFont(Font("Courier New", Font.PLAIN, 12))
        ctx_card = mk_card("Reflection contexts  (what the canary landed inside, "
                           "and what breaks out of it)", self._ctx_area)
        ctx_card.setPreferredSize(Dimension(600, 150))

        # Viewer
        self._req_view  = MessageView("Request")
        self._resp_view = MessageView("Response")
        rr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._req_view, self._resp_view)
        rr.setResizeWeight(0.5); rr.setDividerSize(4); rr.setBackground(BG)

        lower = JSplitPane(JSplitPane.VERTICAL_SPLIT, ctx_card, rr)
        lower.setResizeWeight(0.0); lower.setDividerSize(4); lower.setBackground(BG)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, r_wrap, lower)
        split.setResizeWeight(0.44); split.setDividerSize(5); split.setBackground(BG)
        scan_panel.add(split, BorderLayout.CENTER)

        self._tabs = JTabbedPane()
        self._tabs.setBackground(BG); self._tabs.setForeground(FG)
        self._tabs.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._tabs.addTab("  Queue  ", self._build_queue())
        self._tabs.addTab("  Reflections  ", scan_panel)
        self._tabs.addTab("  XSS Chars  ", self._build_xss())
        self._tabs.addTab("  CRLF  ", self._build_crlf())
        self._tabs.addTab("  Findings  ", self._build_findings())
        self._queue_tab = 0
        self._xss_tab = 2
        self._crlf_tab = 3
        self._findings_tab = 4

        self._root = JPanel(BorderLayout())
        self._root.setBackground(BG)
        self._root.add(self._tabs)
        self._cb.addSuiteTab(self)

    # -----------------------------------------------------------------------
    # Queue tab - the requests waiting to be probed, and their injection points
    # -----------------------------------------------------------------------
    def _build_queue(self):
        p = JPanel(BorderLayout(6, 6))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); top.setBackground(BG)
        top.add(mk_lbl("Right-click requests anywhere in Burp > Send to "
                       "Reflector v6.", 12, color=FG_DIM))
        b_rm = mk_btn("Remove", BG3, FG)
        b_rm.addActionListener(lambda e: self._remove_q())
        b_cl = mk_btn("Clear Queue", BG3, FG)
        b_cl.addActionListener(lambda e: self._clear_q())
        b_sort = mk_btn("Sort by points", ACCENT)
        b_sort.setToolTipText(
            "Reorder the queue so the requests with the most injection points "
            "come first. Probes run through the queue in order, so after a big "
            "site map import this tests the interesting requests first.")
        b_sort.addActionListener(lambda e: self._sort_queue_points())
        b_dedup = mk_btn("De-duplicate", ACCENT)
        b_dedup.setToolTipText(
            "Collapse requests that share an injection surface - same method, "
            "path and parameter names - keeping the first of each.")
        b_dedup.addActionListener(lambda e: self._dedupe_queue())
        top.add(b_rm); top.add(b_cl); top.add(b_sort); top.add(b_dedup)

        # Site map import filters. Both off by default: a host import queues
        # every request Burp has for it, which is what "send the whole host"
        # should mean. Turn them on when a big host makes the queue unwieldy.
        top.add(Box.createHorizontalStrut(10))
        top.add(mk_lbl("Site map import:", 12, True))
        self._ck_imp_static = mk_check("skip static files", False)
        self._ck_imp_static.setToolTipText(
            "Off: .js / .css / images / fonts are queued too. On: they are "
            "skipped unless they carry parameters. Only the path can reflect "
            "on a static file, so they are rarely worth the requests.")
        top.add(self._ck_imp_static)
        self._ck_imp_dedupe = mk_check("one entry per injection surface", False)
        self._ck_imp_dedupe.setToolTipText(
            "Off: every recorded request is queued, so /s?q=1 and /s?q=2 are "
            "two entries. On: they collapse into one, since injecting into q "
            "is the same test either way. Byte-identical requests are dropped "
            "either way.")
        top.add(self._ck_imp_dedupe)
        top.add(Box.createHorizontalStrut(10))
        self._ck_reset_send = mk_check("Clear everything on new Send", True)
        self._ck_reset_send.setToolTipText(
            "On (default): each new 'Send to Reflector v6' wipes the queue and "
            "every result tab first - Reflections, XSS Chars, CRLF and Findings "
            "- so you start clean without clicking Clear on each tab. Off: new "
            "sends add to the current queue and keep existing results (the old "
            "behaviour), for building a queue from several hosts.")
        top.add(self._ck_reset_send)
        p.add(top, BorderLayout.NORTH)

        self._q_model = QueueModel()
        self._q_table = JTable(self._q_model)
        style_table(self._q_table)
        for i, w in enumerate([34, 60, 200, 460, 60]):
            self._q_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._q_table.getSelectionModel().addListSelectionListener(QueueRowSel(self))

        self._p_model = PointModel()
        self._p_table = JTable(self._p_model)
        style_table(self._p_table)
        for i, w in enumerate([60, 160, 300]):
            self._p_table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self._q_req_view = MessageView("Selected request")
        pts = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                         mk_card("Injection points in this request", self._p_table),
                         self._q_req_view)
        pts.setResizeWeight(0.42); pts.setDividerSize(5); pts.setBackground(BG)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           mk_card("Queued Requests", self._q_table), pts)
        split.setResizeWeight(0.4); split.setDividerSize(5); split.setBackground(BG)
        p.add(split, BorderLayout.CENTER)
        return p

    def _set_queue_title(self):
        try:
            n = len(self._queue)
            self._tabs.setTitleAt(self._queue_tab,
                                  "  Queue (%d)  " % n if n else "  Queue  ")
        except Exception:
            pass

    def _mk_result_view(self, loc):
        """A JTable over the shared result model, permanently filtered to one
        reflection location. Sharing the model means a row is added once and
        shows up in whichever tabs it belongs to."""
        t = JTable(self._r_model)
        style_table(t)
        srt = TableRowSorter(self._r_model)
        srt.setComparator(0, NumComparator())
        srt.setComparator(9, NumComparator())
        t.setRowSorter(srt)
        rend = ResultRenderer()
        for i in range(self._r_model.getColumnCount()):
            t.getColumnModel().getColumn(i).setCellRenderer(rend)
        for i, w in enumerate([34, 52, 56, 130, 48, 110, 60, 62, 128, 44,
                               250, 300]):
            t.getColumnModel().getColumn(i).setPreferredWidth(w)
        t.getSelectionModel().addListSelectionListener(ResultRowSel(self, t))
        self._views.append({"t": t, "s": srt, "loc": loc})
        return t

    def _active_table(self):
        i = self._rt_tabs.getSelectedIndex()
        if 0 <= i < len(self._views):
            return self._views[i]["t"]
        return self._views[0]["t"]

    def _set_view_titles(self):
        for (i, title, n) in ((0, "All", self._n_all), (1, "Body", self._n_body),
                              (2, "Headers", self._n_hdr)):
            try:
                self._rt_tabs.setTitleAt(i, "  %s (%d)  " % (title, n))
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # XSS Chars tab - reflected points resent with the breakout probe
    # -----------------------------------------------------------------------
    def _build_xss(self):
        p = JPanel(BorderLayout(6, 6))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        t1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t1.setBackground(BG)
        t1.add(mk_lbl("Reflected points resent as  %s  -  the Reflected chars "
                      "column is which of  %s  came back raw"
                      % (XSS_PROBE, " ".join(XSS_CHARS)), 11, color=FG_DIM))
        t2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t2.setBackground(BG)
        self._xtg_hot = JToggleButton("High/Medium only")
        self._xtg_hot.setBackground(BG3); self._xtg_hot.setForeground(FG)
        self._xtg_hot.setFocusPainted(False); self._xtg_hot.setBorderPainted(False)
        self._xtg_hot.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._xtg_hot.addActionListener(lambda e: self._xss_filter())
        t2.add(self._xtg_hot)
        self._xtg_nohdr = JToggleButton("Hide header reflections")
        self._xtg_nohdr.setBackground(BG3); self._xtg_nohdr.setForeground(FG)
        self._xtg_nohdr.setFocusPainted(False); self._xtg_nohdr.setBorderPainted(False)
        self._xtg_nohdr.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._xtg_nohdr.setToolTipText("Hide rows whose probe came back only in a "
                                       "response header (Location / Set-Cookie / ...) "
                                       "- those are CRLF / redirect leads, not body XSS")
        self._xtg_nohdr.addActionListener(lambda e: self._xss_filter())
        t2.add(self._xtg_nohdr)
        self._xhdr_filter = XssNonHeaderFilter(self)
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_xss_repeater())
        t2.add(b_rep)
        b_cl = mk_btn("Clear", BG3, FG)
        b_cl.addActionListener(lambda e: self._clear_xss())
        t2.add(b_cl)
        top = JPanel(BorderLayout()); top.setBackground(BG)
        top.add(t1, BorderLayout.NORTH); top.add(t2, BorderLayout.SOUTH)
        p.add(top, BorderLayout.NORTH)

        self._x_model = XssModel()
        self._x_table = JTable(self._x_model)
        style_table(self._x_table)
        self._x_sorter = TableRowSorter(self._x_model)
        self._x_sorter.setComparator(0, NumComparator())
        self._x_table.setRowSorter(self._x_sorter)
        xrend = XssRenderer()
        for i in range(self._x_model.getColumnCount()):
            self._x_table.getColumnModel().getColumn(i).setCellRenderer(xrend)
        for i, w in enumerate([34, 56, 52, 130, 48, 110, 60, 56, 150, 120,
                               90, 230, 280]):
            self._x_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._x_table.getSelectionModel().addListSelectionListener(XssRowSel(self))

        self._x_req_view  = MessageView("Request  (probe: %s)" % XSS_PROBE)
        self._x_resp_view = MessageView("Response")
        xr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._x_req_view, self._x_resp_view)
        xr.setResizeWeight(0.5); xr.setDividerSize(4); xr.setBackground(BG)

        xsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                            mk_card("XSS char reflections", self._x_table), xr)
        xsplit.setResizeWeight(0.45); xsplit.setDividerSize(4); xsplit.setBackground(BG)
        p.add(xsplit, BorderLayout.CENTER)
        return p

    def _xss_filter(self):
        filters = ArrayList()
        if self._xtg_hot.isSelected():
            self._xtg_hot.setBackground(GREEN); self._xtg_hot.setForeground(Color.WHITE)
            filters.add(RowFilter.regexFilter("^(High|Medium)$", 1))
        else:
            self._xtg_hot.setBackground(BG3); self._xtg_hot.setForeground(FG)
        if self._xtg_nohdr.isSelected():
            self._xtg_nohdr.setBackground(GREEN); self._xtg_nohdr.setForeground(Color.WHITE)
            filters.add(self._xhdr_filter)
        else:
            self._xtg_nohdr.setBackground(BG3); self._xtg_nohdr.setForeground(FG)
        if filters.size() > 0:
            self._x_sorter.setRowFilter(RowFilter.andFilter(filters))
        else:
            self._x_sorter.setRowFilter(None)

    def _show_xss(self, view_row):
        mr = self._x_table.convertRowIndexToModel(view_row)
        n  = self._x_model.getValueAt(mr, 0)
        data = self._xstored.get(int(str(n)))
        if data:
            self._x_req_view.set_text(data[0])
            self._x_resp_view.set_text(data[1])
            self._x_resp_view.search_for(XSS_PREFIX)

    def _clear_xss(self):
        self._x_model.setRowCount(0); self._xstored = {}; self._xheader = {}; self._xseq = 1
        self._x_req_view.set_text(""); self._x_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._xss_tab, "  XSS Chars  ")
        except Exception:
            pass

    def _send_xss_repeater(self):
        r = self._x_table.getSelectedRow()
        if r < 0:
            return
        mr = self._x_table.convertRowIndexToModel(r)
        data = self._xstored.get(int(str(self._x_model.getValueAt(mr, 0))))
        if not data:
            return
        req_str, resp_str, svc, probe_bytes = data
        if svc is None or probe_bytes is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", probe_bytes,
                                    "XSS " + str(self._x_model.getValueAt(mr, 0)))
        except Exception as ex:
            print("[Reflector v6] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # CRLF tab - header reflections resent with CRLF header-injection payloads
    # -----------------------------------------------------------------------
    def _build_crlf(self):
        p = JPanel(BorderLayout(6, 6))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        t1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t1.setBackground(BG)
        t1.add(mk_lbl("Header reflections resent with %d CRLF payloads - a row "
                      "is High when the server grew a real '%s' header line from "
                      "an injected %%0d%%0a" % (len(CRLF_PAYLOADS), CRLF_HDR),
                      11, color=FG_DIM))
        t2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t2.setBackground(BG)
        self._ctg_hot = JToggleButton("Confirmed only")
        self._ctg_hot.setBackground(BG3); self._ctg_hot.setForeground(FG)
        self._ctg_hot.setFocusPainted(False); self._ctg_hot.setBorderPainted(False)
        self._ctg_hot.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._ctg_hot.addActionListener(lambda e: self._crlf_filter())
        t2.add(self._ctg_hot)
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_crlf_repeater())
        t2.add(b_rep)
        b_cl = mk_btn("Clear", BG3, FG)
        b_cl.addActionListener(lambda e: self._clear_crlf())
        t2.add(b_cl)
        top = JPanel(BorderLayout()); top.setBackground(BG)
        top.add(t1, BorderLayout.NORTH); top.add(t2, BorderLayout.SOUTH)
        p.add(top, BorderLayout.NORTH)

        self._c_model = CrlfModel()
        self._c_table = JTable(self._c_model)
        style_table(self._c_table)
        self._c_sorter = TableRowSorter(self._c_model)
        self._c_sorter.setComparator(0, NumComparator())
        self._c_table.setRowSorter(self._c_sorter)
        crend = CrlfRenderer()
        for i in range(self._c_model.getColumnCount()):
            self._c_table.getColumnModel().getColumn(i).setCellRenderer(crend)
        for i, w in enumerate([34, 56, 52, 130, 48, 110, 60, 110, 130, 220,
                               200, 240]):
            self._c_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._c_table.getSelectionModel().addListSelectionListener(CrlfRowSel(self))

        self._c_req_view  = MessageView("Request  (CRLF payload)")
        self._c_resp_view = MessageView("Response")
        cr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._c_req_view, self._c_resp_view)
        cr.setResizeWeight(0.5); cr.setDividerSize(4); cr.setBackground(BG)

        csplit = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                            mk_card("CRLF / header injection", self._c_table), cr)
        csplit.setResizeWeight(0.45); csplit.setDividerSize(4); csplit.setBackground(BG)
        p.add(csplit, BorderLayout.CENTER)
        return p

    def _crlf_filter(self):
        if self._ctg_hot.isSelected():
            self._ctg_hot.setBackground(GREEN); self._ctg_hot.setForeground(Color.WHITE)
            self._c_sorter.setRowFilter(RowFilter.regexFilter("^High$", 1))
        else:
            self._ctg_hot.setBackground(BG3); self._ctg_hot.setForeground(FG)
            self._c_sorter.setRowFilter(None)

    def _show_crlf(self, view_row):
        mr = self._c_table.convertRowIndexToModel(view_row)
        n  = self._c_model.getValueAt(mr, 0)
        data = self._cstored.get(int(str(n)))
        if data:
            self._c_req_view.set_text(data[0])
            self._c_resp_view.set_text(data[1])
            self._c_resp_view.search_for(CRLF_VAL)

    def _clear_crlf(self):
        self._c_model.setRowCount(0); self._cstored = {}; self._cseq = 1
        self._c_req_view.set_text(""); self._c_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._crlf_tab, "  CRLF  ")
        except Exception:
            pass

    def _reset_crlf_ui(self):
        self._c_model.setRowCount(0)
        self._c_req_view.set_text(""); self._c_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._crlf_tab, "  CRLF  ")
        except Exception:
            pass

    def _send_crlf_repeater(self):
        r = self._c_table.getSelectedRow()
        if r < 0:
            return
        mr = self._c_table.convertRowIndexToModel(r)
        data = self._cstored.get(int(str(self._c_model.getValueAt(mr, 0))))
        if not data:
            return
        req_str, resp_str, svc, probe_bytes = data
        if svc is None or probe_bytes is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", probe_bytes,
                                    "CRLF " + str(self._c_model.getValueAt(mr, 0)))
        except Exception as ex:
            print("[Reflector v6] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # Findings tab - JSON reflections that survive an Accept: text/html replay
    # -----------------------------------------------------------------------
    def _build_findings(self):
        p = JPanel(BorderLayout(6, 6))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # label on its own row so it cannot wrap over the table below
        t1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t1.setBackground(BG)
        t1.add(mk_lbl("JSON reflections replayed with Accept: %s  -  High means the "
                      "content type flipped to HTML and the canary still reflects"
                      % ACCEPT_PROBE, 11, color=FG_DIM))
        t2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); t2.setBackground(BG)
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_finding_repeater())
        t2.add(b_rep)
        b_cl = mk_btn("Clear", BG3, FG)
        b_cl.addActionListener(lambda e: self._clear_f())
        t2.add(b_cl)
        top = JPanel(BorderLayout()); top.setBackground(BG)
        top.add(t1, BorderLayout.NORTH); top.add(t2, BorderLayout.SOUTH)
        p.add(top, BorderLayout.NORTH)

        self._f_model = FindingsModel()
        self._f_table = JTable(self._f_model)
        style_table(self._f_table)
        fs = TableRowSorter(self._f_model)
        fs.setComparator(0, NumComparator())
        self._f_table.setRowSorter(fs)
        frend = FindingsRenderer()
        for i in range(self._f_model.getColumnCount()):
            self._f_table.getColumnModel().getColumn(i).setCellRenderer(frend)
        for i, w in enumerate([34, 62, 150, 52, 120, 62, 110, 150, 56, 300]):
            self._f_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._f_table.getSelectionModel().addListSelectionListener(FindingRowSel(self))

        self._f_req_view  = MessageView("Request  (Accept: %s)" % ACCEPT_PROBE)
        self._f_resp_view = MessageView("Response")
        fr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._f_req_view, self._f_resp_view)
        fr.setResizeWeight(0.5); fr.setDividerSize(4); fr.setBackground(BG)

        fsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                            mk_card("Findings", self._f_table), fr)
        fsplit.setResizeWeight(0.45); fsplit.setDividerSize(4); fsplit.setBackground(BG)
        p.add(fsplit, BorderLayout.CENTER)
        return p

    def _show_finding(self, view_row):
        mr = self._f_table.convertRowIndexToModel(view_row)
        n  = self._f_model.getValueAt(mr, 0)
        data = self._fstored.get(int(str(n)))
        if data:
            self._f_req_view.set_text(data[0])
            self._f_resp_view.set_text(data[1])
            self._f_resp_view.search_for(CANARY)

    def _clear_f(self):
        self._f_model.setRowCount(0); self._fstored = {}; self._fseq = 1
        self._f_req_view.set_text(""); self._f_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._findings_tab, "  Findings  ")
        except Exception:
            pass

    def _send_finding_repeater(self):
        r = self._f_table.getSelectedRow()
        if r < 0:
            return
        mr = self._f_table.convertRowIndexToModel(r)
        data = self._fstored.get(int(str(self._f_model.getValueAt(mr, 0))))
        if not data:
            return
        req_str, resp_str, svc, modified = data
        if svc is None or modified is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", modified, "HTML " + str(
                                        self._f_model.getValueAt(mr, 0)))
        except Exception as ex:
            print("[Reflector v6] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # Context menu
    # -----------------------------------------------------------------------
    def createMenuItems(self, inv):
        lst = ArrayList()
        item = JMenuItem("Send to Reflector v6")
        item.addActionListener(lambda e: self._recv(inv))
        lst.add(item)
        rec = JMenuItem("Send whole host(s) from site map to Reflector v6")
        rec.addActionListener(lambda e: self._recv_sitemap(inv))
        lst.add(rec)
        return lst

    def _entry_from(self, msg):
        """A queue entry for one request/response, or None if it is unusable."""
        req = msg.getRequest()
        svc = msg.getHttpService()
        if req is None or svc is None:
            return None
        raw = self._h.bytesToString(req)
        reqline, headers, body, sep = self._split_req(raw)
        parts  = reqline.split(" ")
        method = parts[0] if parts else "?"
        target = parts[1] if len(parts) > 1 else "/"
        return {"raw": raw, "svc": svc, "method": method,
                "host": str(svc.getHost()), "path": target.split("?", 1)[0],
                "points": self._parse_points(raw)}

    def _add_entry(self, entry):
        self._queue.append(entry)
        self._q_model.addRow([len(self._queue), entry["method"], entry["host"],
                              entry["path"], len(entry["points"])])

    def _endpoint_sig(self, entry, surface_only):
        """What counts as "already queued" during a site map import.

        surface_only collapses /u?id=1 and /u?id=2 into one entry, because
        injecting into id is the same test either way. Otherwise only a
        byte-identical request is treated as a duplicate, so everything the
        host actually has lands in the queue."""
        if surface_only:
            pts = sorted((it.get("sig") or (it["kind"] + ":" + it["name"]))
                         for it in entry["points"])
            return "%s %s %s [%s]" % (entry["method"], entry["host"],
                                      entry["path"], ",".join(pts))
        return entry["raw"]

    def _msg_url(self, msg):
        """The URL of a site map entry.

        getUrl() first, deprecated or not: a host or folder node in the Site
        map has a URL but often no request bytes behind it, and in that case
        analyzeRequest() gives nothing - which is exactly why deriving the URL
        through the helpers alone silently found no hosts to expand."""
        try:
            u = msg.getUrl()
            if u is not None:
                return strip_default_port(str(u))
        except Exception:
            pass
        try:
            u = self._h.analyzeRequest(msg).getUrl()
            if u is not None:
                return strip_default_port(str(u))
        except Exception:
            pass
        return ""

    def _reset_all(self):
        """Wipe the queue and every result tab - Reflections, XSS Chars, CRLF
        and Findings - so a new Send starts from nothing. Any scan or recheck in
        flight is stopped first, since its output is about to be cleared."""
        self._scan = self._xscan = self._cscan = False
        self._clear_q()
        self._clear_r()
        self._clear_xss()
        self._clear_crlf()
        self._clear_f()

    def _reset_if_enabled(self):
        """Clear everything when the Queue tab's 'Clear everything on new Send'
        box is ticked. Called at the start of each Send, once we know there is
        something to queue."""
        try:
            if self._ck_reset_send.isSelected():
                self._reset_all()
        except Exception as ex:
            print("[Reflector v6] reset-on-send failed: %s" % ex)

    def _recv(self, inv):
        msgs = inv.getSelectedMessages()
        if not msgs:
            return
        self._reset_if_enabled()        # fresh slate before this batch, if asked
        added = 0
        for msg in msgs:
            try:
                entry = self._entry_from(msg)
                if entry is None:
                    continue
                self._add_entry(entry)
                added += 1
            except Exception as ex:
                print("[Reflector v6] load error: %s" % ex)
        if added:
            SwingUtilities.invokeLater(self._set_queue_title)
            print("[Reflector v6] queued %d request(s)" % added)

    def _selection_prefixes(self, inv):
        """Where to pull the site map from, for whatever the user right-clicked.

        Two sources, because neither covers every case on its own: the Site map
        tree selection (the only thing that sees a host or folder node), and
        the selected messages (the only thing that works in the site map table,
        proxy history, Repeater and so on)."""
        try:
            ctx = inv.getInvocationContext()
        except Exception:
            ctx = -1
        prefixes = []
        msgs = []
        try:
            msgs = list(inv.getSelectedMessages() or [])
        except Exception:
            msgs = []
        # A Site map tree selection hands back one entry per selected node, and
        # that node's own URL is the branch to expand - a host node gives
        # "https://host", a folder node "https://host/api". Anywhere else (site
        # map table, proxy history, Repeater) the selection is real requests, so
        # the host they belong to is what "whole host" means.
        tree_ctx = (ctx == CTX_SITE_MAP_TREE)
        for msg in msgs:
            u = self._msg_url(msg)
            if not u:
                continue
            r = u if tree_ctx else url_host_root(u)
            if r not in prefixes:
                prefixes.append(r)

        # Only if that found nothing: read the selection off the tree component.
        tree = None
        if not prefixes:
            try:
                tree = jtree_from_event(inv.getInputEvent())
            except Exception as ex:
                print("[Reflector v6] could not reach the site map tree: %s" % ex)
            if tree is not None:
                prefixes = tree_prefixes(tree)
                if not prefixes:
                    for labels in tree_selection_labels(tree):
                        print("[Reflector v6] unrecognised site map node: %r" % (labels,))

        prefixes = drop_nested(prefixes)
        print("[Reflector v6] context=%s, %d selected message(s), tree=%s, "
              "%d branch(es): %s"
              % (ctx, len(msgs), "yes" if tree is not None else "no",
                 len(prefixes), ", ".join(prefixes) or "-"))
        return prefixes

    def _recv_sitemap(self, inv):
        """Everything Burp has recorded under the selected host(s) / branch(es)."""
        roots = self._selection_prefixes(inv)
        if not roots:
            print("[Reflector v6] nothing usable in that selection - highlight a "
                  "host (or any request under it) in the Site map and retry.")
            return

        items = []
        for r in roots:
            try:
                got = list(self._cb.getSiteMap(r) or [])
            except Exception as ex:
                print("[Reflector v6] getSiteMap(%s) failed: %s" % (r, ex))
                continue
            # getSiteMap matches on the URL text, so a bare host prefix also
            # matches a different host that merely starts the same way.
            want = url_authority(r)
            keep = []
            for m in got:
                u = self._msg_url(m)
                if not u or (want and url_authority(u) != want):
                    continue
                keep.append(m)
            print("[Reflector v6] site map %s -> %d item(s)%s"
                  % (r, len(keep),
                     "  (%d other host(s) ignored)" % (len(got) - len(keep))
                     if len(got) != len(keep) else ""))
            items.extend(keep)
        if not items:
            # nothing recorded under those prefixes: fall back to the selection
            # (_recv does its own reset, so none is needed here)
            print("[Reflector v6] site map has nothing under %s - queueing the "
                  "selected request(s) instead." % ", ".join(roots))
            self._recv(inv)
            return

        # About to add a fresh batch: clear first, if asked. Done before the
        # 'seen' set is built so it starts from an empty queue.
        self._reset_if_enabled()
        f_static = self._ck_imp_static.isSelected()
        f_surface = self._ck_imp_dedupe.isSelected()
        seen = set(self._endpoint_sig(e, f_surface) for e in self._queue)
        added = dupes = static = bad = norequest = 0
        capped = False
        for msg in items:
            if added >= MAX_IMPORT:
                capped = True
                break
            try:
                req = msg.getRequest()
                if req is None:
                    # A tree node Burp drew for a path segment, or a link it
                    # inferred but never requested: a URL with nothing to
                    # replay. On a big site map these are most of the skips.
                    norequest += 1
                    continue
                u = self._msg_url(msg)
                raw = self._h.bytesToString(req)
                if f_static and is_static_url(
                        u, bool(self._split_req(raw)[2].strip())):
                    static += 1
                    continue
                entry = self._entry_from(msg)
                if entry is None:
                    bad += 1
                    continue
                sig = self._endpoint_sig(entry, f_surface)
                if sig in seen:
                    dupes += 1
                    continue
                seen.add(sig)
                self._add_entry(entry)
                added += 1
            except Exception as ex:
                bad += 1
                print("[Reflector v6] import error: %s" % ex)

        notes = []
        if norequest:
            notes.append("%d never requested (folder / inferred link)" % norequest)
        if dupes:
            notes.append("%d %s" % (dupes, "duplicate endpoint(s)" if f_surface
                                    else "identical request(s)"))
        if static:
            notes.append("%d static file(s)" % static)
        if bad:
            notes.append("%d unusable" % bad)
        tail = ("  -  skipped " + ", ".join(notes)) if notes else ""
        if capped:
            tail += ("  -  stopped at the %d item cap; narrow the selection to "
                     "queue the rest" % MAX_IMPORT)
        print("[Reflector v6] site map import: queued %d of %d item(s)%s"
              % (added, len(items), tail))
        SwingUtilities.invokeLater(self._set_queue_title)

    # -----------------------------------------------------------------------
    # Request parsing + injection
    # -----------------------------------------------------------------------
    def _split_req(self, raw):
        head, sep, body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        return lines[0], lines[1:], body, (sep if sep else "\r\n\r\n")

    def _join_req(self, reqline, headers, body, sep):
        return "\r\n".join([reqline] + headers) + sep + body

    def _pairs(self, qs):
        res = []
        if qs:
            for part in qs.split("&"):
                k, eq, v = part.partition("=")
                res.append([k, v, bool(eq)])
        return res

    def _rebuild_qs(self, pairs):
        return "&".join(k + ("=" + v if eq else "") for (k, v, eq) in pairs)

    def _set_pair(self, pairs, name, value):
        done = False
        for pr in pairs:
            if pr[0] == name and not done:
                pr[1] = value; pr[2] = True; done = True
        return pairs

    def _content_type(self, headers):
        for hl in headers:
            if hl.lower().startswith("content-type:"):
                return hl.split(":", 1)[1].strip().lower()
        return ""

    def _parse_points(self, raw):
        items = []
        reqline, headers, body, sep = self._split_req(raw)
        parts  = reqline.split(" ")
        target = parts[1] if len(parts) > 1 else "/"
        path, q, query = target.partition("?")

        # Path (Replace mode adds the canary as a new segment, Append glues it
        # onto the tail of the last segment)
        items.append({"kind": "path", "name": "(path)", "value": path})

        for (k, v, eq) in self._pairs(query):
            if k:
                items.append({"kind": "url", "name": k, "value": v})

        ct = self._content_type(headers)
        b = body.strip()
        if b:
            if "json" in ct or b[:1] in "{[":
                items += self._json_points(b)
            else:
                for (k, v, eq) in self._pairs(b):
                    if k:
                        items.append({"kind": "body", "name": k, "value": v})

        seen, out = set(), []
        for it in items:
            key = it.get("sig") or (it["kind"] + ":" + it["name"])
            if key in seen:
                continue
            seen.add(key); out.append(it)
        return out

    def _json_points(self, body):
        try:
            import json
            data = json.loads(body)
        except Exception:
            return []
        pts, seen = [], set()
        def leaf(path):
            for s in reversed(path):
                if not s.isdigit():
                    return s
            return path[-1] if path else "json"
        def norm(path):
            return ".".join("[]" if s.isdigit() else s for s in path)
        def walk(o, path):
            if isinstance(o, dict):
                for k in o:
                    walk(o[k], path + [str(k)])
            elif isinstance(o, list):
                for i in range(len(o)):
                    walk(o[i], path + [str(i)])
            else:
                nk = norm(path)
                if nk in seen:
                    return
                seen.add(nk)
                pts.append({"kind": "json", "name": leaf(path), "path": path,
                            "value": "" if o is None else str(o), "sig": "json:" + nk})
        walk(data, [])
        return pts

    def _set_json(self, body, path, value):
        try:
            import json
            data = json.loads(body); ref = data
            for k in path[:-1]:
                ref = ref[int(k)] if isinstance(ref, list) else ref[k]
            last = path[-1]
            if isinstance(ref, list):
                ref[int(last)] = value
            else:
                ref[last] = value
            return json.dumps(data)
        except Exception:
            return body

    def _fix_cl(self, headers, body):
        blen = len(self._h.stringToBytes(body)) if body else 0
        out = []
        for hl in headers:
            if hl.lower().startswith("content-length:"):
                out.append("Content-Length: %d" % blen)
            else:
                out.append(hl)
        return out

    def _injected_value(self, item, value, mode):
        """What the parameter is set to. Replace mode throws the original value
        away; append mode glues the canary onto the end of it, so the endpoint
        still gets a value it recognises (?id=42xssezwin) and routing, type
        coercion and validation that would reject a bare canary stay happy."""
        if mode != "append":
            return value
        return (item.get("value") or "") + value

    def _append_is_redundant(self, item, mode):
        """True when appending would build the exact request replace already
        builds: an empty/null original value, or the root path. Skipped in
        Both mode so the second pass does not re-send identical probes."""
        if mode != "append":
            return False
        cur = item.get("value") or ""
        if item["kind"] == "path":
            return not cur.rstrip("/")
        return not cur

    def _inject(self, raw, item, value, mode="replace"):
        reqline, headers, body, sep = self._split_req(raw)
        kind = item["kind"]
        inj  = self._injected_value(item, value, mode)
        if kind == "path":
            parts = reqline.split(" ")
            path, q, query = parts[1].partition("?")
            base = path.rstrip("/")
            if mode == "append":
                # onto the tail of the last segment: /api/user -> /api/userxssezwin
                newpath = (base + value) if base else ("/" + value)
            else:
                # as its own new segment: /api/user -> /api/user/xssezwin
                newpath = base + "/" + value
            parts[1] = newpath + (("?" + query) if q else "")
            reqline = " ".join(parts)
        elif kind == "url":
            parts = reqline.split(" ")
            path, q, query = parts[1].partition("?")
            pairs = self._set_pair(self._pairs(query), item["name"], inj)
            parts[1] = path + ("?" + self._rebuild_qs(pairs) if pairs else "")
            reqline = " ".join(parts)
        elif kind == "body":
            pairs = self._set_pair(self._pairs(body.strip()), item["name"], inj)
            body = self._rebuild_qs(pairs)
        elif kind == "json":
            body = self._set_json(body, item.get("path", [item["name"]]), inj)
        headers = self._fix_cl(headers, body)
        return self._h.stringToBytes(self._join_req(reqline, headers, body, sep))

    # -----------------------------------------------------------------------
    # Response helpers
    # -----------------------------------------------------------------------
    def _resp_header(self, resp, name):
        """Value of a response header, or '' - headers only, never the body."""
        if not resp:
            return ""
        head = resp.split("\r\n\r\n", 1)[0]
        pre = name.lower() + ":"
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith(pre):
                return line.split(":", 1)[1].strip()
        return ""

    def _resp_ct(self, resp):
        return self._resp_header(resp, "Content-Type").lower()

    def _is_json_ct(self, ct):
        return ("json" in ct) or ct.endswith("+json")

    def _is_html_ct(self, ct):
        return ("text/html" in ct) or ("xhtml" in ct)

    def _set_header(self, headers, name, value):
        """Match-replace one header's value; append it if the request has none."""
        pre, out, done = name.lower() + ":", [], False
        for hl in headers:
            if hl.lower().startswith(pre):
                if not done:
                    out.append("%s: %s" % (name, value)); done = True
                # drop any duplicate Accept lines
            else:
                out.append(hl)
        if not done:
            out.append("%s: %s" % (name, value))
        return out

    def _with_accept(self, modified_bytes, value):
        """The same request with Accept: <value> and nothing else changed."""
        raw = self._h.bytesToString(modified_bytes)
        reqline, headers, body, sep = self._split_req(raw)
        headers = self._set_header(headers, "Accept", value)
        return self._h.stringToBytes(self._join_req(reqline, headers, body, sep))

    # -----------------------------------------------------------------------
    # Accept: text/html replay - the content-type-confusion check
    # -----------------------------------------------------------------------
    def _accept_recheck(self, entry, it, modified, json_ct, interval, t_main,
                        mode="replace"):
        """Replay a JSON reflection with Accept: text/html. Raises a finding if
        the endpoint answers with HTML. Returns True if a request was sent.

        t_main is when the request this is rechecking went out: the probe waits
        out the rest of that slot first, so the extra request does not push the
        instantaneous rate over the cap."""
        rem = interval - (time.time() - t_main)
        if rem > 0:
            time.sleep(rem)
        t0 = time.time()
        try:
            probe = self._with_accept(modified, ACCEPT_PROBE)
            resp  = self._cb.makeHttpRequest(entry["svc"], probe)
            rb    = resp.getResponse()
            rs    = self._h.bytesToString(rb) if rb else ""
            reqs  = self._h.bytesToString(probe)
        except Exception as ex:
            print("[Reflector v6] accept recheck failed: %s" % ex)
            return False

        new_ct = self._resp_ct(rs)
        ds     = decode_message(rs)
        cnt    = ds.lower().count(CANARY)

        if self._is_html_ct(new_ct):
            notes = []
            disp = self._resp_header(rs, "Content-Disposition")
            if disp and "attachment" in disp.lower():
                notes.append("Content-Disposition: attachment (downloads, will not render)")
                sev = "Medium"
            elif cnt > 0:
                sev = "High"
            else:
                sev = "Medium"
            if cnt > 0:
                idx = ds.lower().find(CANARY)
                s = max(0, idx - 30); e = min(len(ds), idx + len(CANARY) + 30)
                notes.insert(0, display_text(ds[s:e]).replace("\n", " "))
            else:
                notes.insert(0, "content type flips to HTML but this parameter "
                                "no longer reflects")
            self._add_finding(sev, entry, it, json_ct, new_ct or "(none)",
                              "YES" if cnt > 0 else "no", "  |  ".join(notes),
                              reqs, rs, probe, mode)
        # keep the same pacing for this extra request
        rem = interval - (time.time() - t0)
        if rem > 0:
            time.sleep(rem)
        return True

    def _add_finding(self, sev, entry, it, json_ct, html_ct, reflects, notes,
                     req_str, resp_str, probe_bytes, mode="replace"):
        with self._lock:
            fid = self._fseq; self._fseq += 1
            self._fstored[fid] = (req_str, resp_str, entry["svc"], probe_bytes)
        row = [fid, sev, entry["path"], KIND_LABEL.get(it["kind"], it["kind"]),
               it["name"], MODE_LABEL.get(mode, mode), json_ct, html_ct,
               reflects, notes]
        SwingUtilities.invokeLater(lambda: self._add_finding_row(row))

    def _add_finding_row(self, row):
        self._f_model.addRow(row)
        try:
            self._tabs.setTitleAt(self._findings_tab,
                                  "  Findings (%d)  " % self._f_model.getRowCount())
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Scan (single worker, rate-limited to <= 5 req/s)
    # -----------------------------------------------------------------------
    def _modes(self):
        """Which injection modes this scan runs, in order."""
        if self._rb_both.isSelected():
            return ["replace", "append"]
        if self._rb_append.isSelected():
            return ["append"]
        return ["replace"]

    def _interval(self):
        """Seconds between request starts, from the Req/sec field, clamped to
        the cap. Shared by the scan, the XSS recheck and the CRLF recheck so
        they all obey one knob."""
        try:
            rps = float(self._f_rps.getText().strip() or "5")
        except Exception:
            rps = 5.0
        rps = max(0.2, min(MAX_RPS, rps))
        self._f_rps.setText(str(int(rps)) if rps == int(rps) else str(rps))
        return 1.0 / rps

    def _busy_ui(self, running):
        """One switch for all three long-running jobs: while any is going the
        three start buttons are disabled and Stop is live."""
        self._btn_start.setEnabled(not running)
        self._btn_xss.setEnabled(not running)
        self._btn_crlf.setEnabled(not running)
        self._btn_stop.setEnabled(running)

    def _start(self):
        if self._scan or self._xscan or self._cscan:
            return
        if not self._queue:
            self._prog.setString("Queue empty"); return
        interval = self._interval()
        self._scan = True
        self._busy_ui(True)
        t = threading.Thread(target=self._worker, args=(list(self._queue), interval))
        t.setDaemon(True); t.start()

    def _stop(self):
        self._scan = False
        self._xscan = False
        self._cscan = False

    def _worker(self, snapshot, interval):
        try:
            modes = self._modes()
            # (entry, item, mode) triples, append probes that would duplicate a
            # replace probe dropped so Both mode does not burn requests on them
            work = []
            for entry in snapshot:
                for it in entry["points"]:
                    for mode in modes:
                        if len(modes) > 1 and self._append_is_redundant(it, mode):
                            continue
                        work.append((entry, it, mode))
            total = len(work)
            done = 0
            self._rstored = {}; self._rseq = 1
            self._fstored = {}; self._fseq = 1
            self._kept = 0
            self._n_all = self._n_body = self._n_hdr = 0
            SwingUtilities.invokeLater(self._set_view_titles)
            recheck = self._ck_accept.isSelected()
            keep_all = self._ck_keep.isSelected()
            SwingUtilities.invokeLater(lambda: self._r_model.setRowCount(0))
            SwingUtilities.invokeLater(self._reset_findings_ui)
            for (entry, it, mode) in work:
                if not self._scan:
                    break
                t0 = time.time()
                try:
                    modified = self._inject(entry["raw"], it, CANARY, mode)
                    resp = self._cb.makeHttpRequest(entry["svc"], modified)
                    rb   = resp.getResponse()
                    rs   = self._h.bytesToString(rb) if rb else ""
                    reqs = self._h.bytesToString(modified)
                    # a gzipped or chunked body does not contain the canary
                    # as plain text - search what the body actually says
                    ds   = decode_message(rs)
                    # Headers and body are counted apart: a canary in Location
                    # is a redirect / header injection lead, one in the body is
                    # the XSS primitive, and they are not the same bug.
                    dhead, dsep, dbody = split_head_body(ds)
                    hcnt = dhead.lower().count(CANARY)
                    bcnt = dbody.lower().count(CANARY)
                    cnt  = hcnt + bcnt
                    refl = "YES" if cnt > 0 else "no"
                    where_in = reflect_location(dhead, hcnt, bcnt)
                    ct   = self._resp_ct(rs)
                    ctl  = ct_label(ct)
                    # What it landed inside, per occurrence. Done here on the
                    # worker thread so the table is useful the moment the row
                    # appears, rather than only once something is clicked.
                    ctxs    = reflect_contexts(rs, ct, CANARY) if cnt > 0 else []
                    context, snippet = context_summary(ctxs)
                    detail  = context_detail(ctxs, cnt)
                    rid = self._rseq; self._rseq += 1
                    # Hold the response only when it is worth looking at. The
                    # request is always kept - it is small, and Send to
                    # Repeater needs it.
                    # entry / item / mode ride along so a reflected row can be
                    # re-injected with the XSS breakout probe later.
                    if cnt > 0 or keep_all:
                        self._rstored[rid] = {"req": reqs, "resp": rs,
                                              "svc": entry["svc"],
                                              "bytes": modified, "detail": detail,
                                              "entry": entry, "item": it, "mode": mode}
                        self._kept += len(rs)
                    else:
                        self._rstored[rid] = {"req": reqs, "resp": None,
                                              "svc": entry["svc"],
                                              "bytes": modified, "detail": detail,
                                              "entry": entry, "item": it, "mode": mode}
                    row = [rid, entry["method"], ctl, entry["path"],
                           KIND_LABEL.get(it["kind"], it["kind"]), it["name"],
                           MODE_LABEL.get(mode, mode), refl, where_in, cnt,
                           context, snippet]
                    done += 1
                    pct = int(done * 100.0 / total) if total else 100
                    SwingUtilities.invokeLater(
                        lambda r=row, p=pct, d=done, tt=total:
                            self._add_result(r, p, "%d / %d" % (d, tt)))

                    # JSON reflection -> replay it as Accept: text/html
                    ct = self._resp_ct(rs)
                    if recheck and bcnt > 0 and self._is_json_ct(ct):
                        self._accept_recheck(entry, it, modified, ct,
                                             interval, t0, mode)
                except Exception as ex:
                    print("[Reflector v6] request error: %s" % ex)
                    done += 1
                # rate limit: keep >= interval between request starts
                rem = interval - (time.time() - t0)
                if rem > 0:
                    time.sleep(rem)
        except Exception as ex:
            print("[Reflector v6] worker error: %s" % ex)
        finally:
            self._scan = False
            SwingUtilities.invokeLater(self._done)

    def _add_result(self, row, pct, label):
        self._r_model.addRow(row)
        self._n_all += 1
        where_in = str(row[8] or "")
        if "Body" in where_in:
            self._n_body += 1
        if "Header:" in where_in:
            self._n_hdr += 1
        self._set_view_titles()
        self._prog.setValue(pct); self._prog.setString(label)

    def _done(self):
        self._busy_ui(False)
        self._prog.setValue(100)
        hits = sum(1 for i in range(self._r_model.getRowCount())
                   if str(self._r_model.getValueAt(i, 7)) == "YES")
        nf = self._f_model.getRowCount()
        self._prog.setString("Done - %d reflected (%d body, %d header)%s, %.1f MB kept"
                             % (hits, self._n_body, self._n_hdr,
                                (", %d HTML finding(s)" % nf) if nf else "",
                                self._kept / 1048576.0))

    # -----------------------------------------------------------------------
    # XSS char recheck - resend every reflected point with the breakout probe
    # -----------------------------------------------------------------------
    def _reflected_rids(self):
        """The result ids of every row that reflected the canary, in table
        order, de-duplicated. Reads the shared model, so it is independent of
        which location tab or filter happens to be showing."""
        out, seen = [], set()
        for i in range(self._r_model.getRowCount()):
            if str(self._r_model.getValueAt(i, 7)) != "YES":
                continue
            try:
                rid = int(str(self._r_model.getValueAt(i, 0)))
            except Exception:
                continue
            if rid in seen:
                continue
            seen.add(rid)
            data = self._rstored.get(rid)
            if data and data.get("entry") is not None and data.get("item") is not None:
                out.append(rid)
        return out

    def _xss_recheck_start(self):
        if self._scan or self._xscan or self._cscan:
            return
        rids = self._reflected_rids()
        if not rids:
            self._prog.setString("No reflected rows to recheck")
            print("[Reflector v6] XSS recheck: nothing reflected yet - run a scan "
                  "first, the reflected rows (green) are what gets resent.")
            return
        interval = self._interval()
        self._xscan = True
        self._busy_ui(True)
        print("[Reflector v6] XSS recheck: resending %d reflected point(s) as %s"
              % (len(rids), XSS_PROBE))
        t = threading.Thread(target=self._xss_worker, args=(rids, interval))
        t.setDaemon(True); t.start()

    def _reset_xss_ui(self):
        self._x_model.setRowCount(0)
        self._x_req_view.set_text(""); self._x_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._xss_tab, "  XSS Chars  ")
        except Exception:
            pass

    def _xss_worker(self, rids, interval):
        try:
            total = len(rids)
            done = high = 0
            # Reset the store on the worker thread, not via invokeLater, so a
            # row added below cannot be wiped by a clear that runs after it.
            self._xstored = {}; self._xheader = {}; self._xseq = 1
            SwingUtilities.invokeLater(self._reset_xss_ui)
            for rid in rids:
                if not self._xscan:
                    break
                data = self._rstored.get(rid)
                if not data:
                    done += 1
                    continue
                entry, it, mode = data["entry"], data["item"], data["mode"]
                t0 = time.time()
                try:
                    probe = self._inject(entry["raw"], it, XSS_PROBE, mode)
                    resp  = self._cb.makeHttpRequest(entry["svc"], probe)
                    rb    = resp.getResponse()
                    rs    = self._h.bytesToString(rb) if rb else ""
                    reqs  = self._h.bytesToString(probe)
                    ds    = decode_message(rs)
                    ct    = self._resp_ct(rs)
                    info  = analyze_xss_chars(ds)
                    ctxs  = reflect_contexts(rs, ct, XSS_PREFIX)
                    # Header-only reflection = CRLF / redirect lead, not body
                    # XSS - recorded so the "Hide header reflections" toggle can
                    # drop it. Counted the same way the scan splits head / body.
                    dhead, _dsep, dbody = split_head_body(ds)
                    is_header = (dhead.lower().count(XSS_PREFIX) > 0
                                 and dbody.lower().count(XSS_PREFIX) == 0)
                    if info is None:
                        refl_s, filt_s = "(none)", " ".join(XSS_CHARS)
                        verdict = "probe did not reflect - value rejected or filtered"
                        sev, snip = "low", ""
                    else:
                        refl_s = " ".join(info["reflected"]) or "(none)"
                        # escaped quotes shown with their backslash (\") so the
                        # Filtered column makes plain they came back neutralised.
                        neutralised = (info["encoded"] + info["stripped"]
                                       + ["\\" + c for c in info["escaped"]])
                        filt_s = " ".join(neutralised) or "-"
                        verdict, sev = xss_verdict(
                            ctxs, info["reflected"], info["escaped"])
                        snip = info["snippet"]
                    context, _cs = context_summary(ctxs)
                    xid = self._xseq; self._xseq += 1
                    self._xstored[xid] = (reqs, rs, entry["svc"], probe)
                    self._xheader[xid] = is_header
                    if sev == "High":
                        high += 1
                    row = [xid, sev, entry["method"], entry["path"],
                           KIND_LABEL.get(it["kind"], it["kind"]), it["name"],
                           MODE_LABEL.get(mode, mode), ct_label(ct),
                           context, refl_s, filt_s, verdict, snip]
                    done += 1
                    pct = int(done * 100.0 / total) if total else 100
                    SwingUtilities.invokeLater(
                        lambda r=row, p=pct, d=done, tt=total:
                            self._add_xss_row(r, p, "XSS %d / %d" % (d, tt)))
                except Exception as ex:
                    # Still emit a row so every reflection is accounted for - a
                    # resend that errored is visible, not silently dropped.
                    print("[Reflector v6] XSS recheck error: %s" % ex)
                    xid = self._xseq; self._xseq += 1
                    self._xstored[xid] = ("", "", entry.get("svc"), None)
                    self._xheader[xid] = False
                    row = [xid, "low", entry.get("method", "?"),
                           entry.get("path", "?"),
                           KIND_LABEL.get(it["kind"], it["kind"]), it["name"],
                           MODE_LABEL.get(mode, mode), "-", "(request error)",
                           "(none)", "-", "resend failed: %s" % ex, ""]
                    done += 1
                    pct = int(done * 100.0 / total) if total else 100
                    SwingUtilities.invokeLater(
                        lambda r=row, p=pct, d=done, tt=total:
                            self._add_xss_row(r, p, "XSS %d / %d" % (d, tt)))
                rem = interval - (time.time() - t0)
                if rem > 0:
                    time.sleep(rem)
            self._xss_high = high
        except Exception as ex:
            print("[Reflector v6] XSS worker error: %s" % ex)
        finally:
            self._xscan = False
            SwingUtilities.invokeLater(self._xss_done)

    def _add_xss_row(self, row, pct, label):
        self._x_model.addRow(row)
        try:
            self._tabs.setTitleAt(self._xss_tab,
                                  "  XSS Chars (%d)  " % self._x_model.getRowCount())
        except Exception:
            pass
        self._prog.setValue(pct); self._prog.setString(label)

    def _xss_done(self):
        self._busy_ui(False)
        self._prog.setValue(100)
        n = self._x_model.getRowCount()
        high = getattr(self, "_xss_high", 0)
        self._prog.setString("XSS recheck done - %d point(s), %d High" % (n, high))
        print("[Reflector v6] XSS recheck done - %d point(s) rechecked, %d High"
              % (n, high))

    # -----------------------------------------------------------------------
    # CRLF recheck - resend header reflections with CRLF injection payloads
    # -----------------------------------------------------------------------
    def _crlf_candidates(self):
        """(rid, "In" text) for every reflected row whose canary came back in a
        response header - those are the only ones a header-injection payload can
        act on. De-duplicated, in table order."""
        out, seen = [], set()
        for i in range(self._r_model.getRowCount()):
            if str(self._r_model.getValueAt(i, 7)) != "YES":
                continue
            where = str(self._r_model.getValueAt(i, 8) or "")
            if "Header:" not in where:
                continue
            try:
                rid = int(str(self._r_model.getValueAt(i, 0)))
            except Exception:
                continue
            if rid in seen:
                continue
            seen.add(rid)
            data = self._rstored.get(rid)
            if data and data.get("entry") is not None and data.get("item") is not None:
                out.append((rid, where))
        return out

    def _crlf_recheck_start(self):
        if self._scan or self._xscan or self._cscan:
            return
        cands = self._crlf_candidates()
        if not cands:
            self._prog.setString("No header reflections to recheck")
            print("[Reflector v6] CRLF recheck: no reflection landed in a response "
                  "header - this test needs a 'Header: ...' row (see the Headers "
                  "sub-tab). Run a scan first.")
            return
        interval = self._interval()
        self._cscan = True
        self._busy_ui(True)
        print("[Reflector v6] CRLF recheck: probing %d header reflection(s) with "
              "%d payload(s) each" % (len(cands), len(CRLF_PAYLOADS)))
        t = threading.Thread(target=self._crlf_worker, args=(cands, interval))
        t.setDaemon(True); t.start()

    def _crlf_worker(self, cands, interval):
        try:
            total = len(cands); done = high = 0
            self._cstored = {}; self._cseq = 1
            SwingUtilities.invokeLater(self._reset_crlf_ui)
            for (rid, where) in cands:
                if not self._cscan:
                    break
                data = self._rstored.get(rid)
                if not data:
                    done += 1
                    continue
                entry, it, mode = data["entry"], data["item"], data["mode"]
                hit = None       # (label, evidence, reqs, rs, probe)
                last = None      # (reqs, rs, probe) of the final attempt, for the viewer
                for (label, value, expected) in CRLF_PAYLOADS:
                    if not self._cscan:
                        break
                    t0 = time.time()
                    try:
                        probe = self._inject(entry["raw"], it, value, mode)
                        resp  = self._cb.makeHttpRequest(entry["svc"], probe)
                        rb    = resp.getResponse()
                        rs    = self._h.bytesToString(rb) if rb else ""
                        reqs  = self._h.bytesToString(probe)
                        last  = (reqs, rs, probe)
                        ok, ev = detect_crlf(rs, expected)
                        if ok:
                            hit = (label, ev, reqs, rs, probe)
                    except Exception as ex:
                        print("[Reflector v6] CRLF probe error: %s" % ex)
                    rem = interval - (time.time() - t0)
                    if rem > 0:
                        time.sleep(rem)
                    if hit:
                        break        # first working payload is proof enough

                cid = self._cseq; self._cseq += 1
                if hit:
                    label, ev, reqs, rs, probe = hit
                    verdict = "CRLF injection CONFIRMED - server honoured %s" % label
                    sev = "High"; high += 1
                    payload_s = label; inj_line = ev or (CRLF_HDR + ":" + CRLF_VAL)
                    snip = ev
                    self._cstored[cid] = (reqs, rs, entry["svc"], probe)
                else:
                    reqs, rs, probe = last if last else ("", "", None)
                    payload_s = "-"; inj_line = "-"
                    enc = header_line_with(rs, CRLF_VAL)
                    if enc:
                        verdict = "no injection - value stays encoded in the header"
                        snip = enc
                    else:
                        verdict = ("no injection - payload did not reflect "
                                   "(value may be validated away)")
                        snip = ""
                    sev = "low"
                    self._cstored[cid] = (reqs, rs, entry["svc"], probe)
                row = [cid, sev, entry["method"], entry["path"],
                       KIND_LABEL.get(it["kind"], it["kind"]), it["name"],
                       MODE_LABEL.get(mode, mode), where.replace("Header: ", ""),
                       payload_s, inj_line, verdict, snip]
                done += 1
                pct = int(done * 100.0 / total) if total else 100
                SwingUtilities.invokeLater(
                    lambda r=row, p=pct, d=done, tt=total:
                        self._add_crlf_row(r, p, "CRLF %d / %d" % (d, tt)))
            self._crlf_high = high
        except Exception as ex:
            print("[Reflector v6] CRLF worker error: %s" % ex)
        finally:
            self._cscan = False
            SwingUtilities.invokeLater(self._crlf_done)

    def _add_crlf_row(self, row, pct, label):
        self._c_model.addRow(row)
        try:
            self._tabs.setTitleAt(self._crlf_tab,
                                  "  CRLF (%d)  " % self._c_model.getRowCount())
        except Exception:
            pass
        self._prog.setValue(pct); self._prog.setString(label)

    def _crlf_done(self):
        self._busy_ui(False)
        self._prog.setValue(100)
        n = self._c_model.getRowCount()
        high = getattr(self, "_crlf_high", 0)
        self._prog.setString("CRLF recheck done - %d point(s), %d confirmed" % (n, high))
        print("[Reflector v6] CRLF recheck done - %d point(s), %d confirmed" % (n, high))

    # -----------------------------------------------------------------------
    # Filters / display / queue mgmt
    # -----------------------------------------------------------------------
    def _toggle_refl(self):
        if self._tg_refl.isSelected():
            self._tg_refl.setBackground(GREEN); self._tg_refl.setForeground(Color.WHITE)
        else:
            self._tg_refl.setBackground(BG3); self._tg_refl.setForeground(FG)
        self._apply_filters()

    def _apply_filters(self):
        try:
            for v in self._views:
                filters = ArrayList()
                if self._rb_get.isSelected():
                    filters.add(RowFilter.regexFilter("(?i)^GET$", 1))
                elif self._rb_write.isSelected():
                    filters.add(RowFilter.regexFilter("(?i)^(POST|PUT|PATCH)$", 1))
                if self._tg_refl.isSelected():
                    filters.add(RowFilter.regexFilter("^YES$", 7))
                if v["loc"]:
                    filters.add(RowFilter.regexFilter(v["loc"], 8))
                if filters.size() > 0:
                    v["s"].setRowFilter(RowFilter.andFilter(filters))
                else:
                    v["s"].setRowFilter(None)
        except Exception as ex:
            print("[Reflector v6] filter error: %s" % ex)

    def _show_queue(self, view_row):
        if not (0 <= view_row < len(self._queue)):
            return
        e = self._queue[view_row]
        self._q_req_view.set_text(e["raw"])
        self._p_model.setRowCount(0)
        for it in e["points"]:
            val = it.get("value") or ""
            if len(val) > 160:
                val = val[:160] + " ..."
            self._p_model.addRow([KIND_LABEL.get(it["kind"], it["kind"]),
                                  it["name"], display_text(val).replace("\n", " ")])

    def _show_result(self, table, view_row):
        mr = table.convertRowIndexToModel(view_row)
        n  = self._r_model.getValueAt(mr, 0)
        data = self._rstored.get(int(str(n)))
        if data:
            self._req_view.set_text(data["req"])
            resp = data["resp"]
            self._resp_view.set_text(resp if resp is not None else NOT_RETAINED)
            if resp is not None:
                self._resp_view.search_for(CANARY)
            self._ctx_area.setText(data.get("detail") or "")
            self._ctx_area.setCaretPosition(0)

    def _remove_q(self):
        rows = sorted(set(self._q_table.getSelectedRows()), reverse=True)
        for r in rows:
            if 0 <= r < len(self._queue):
                del self._queue[r]
        self._q_model.setRowCount(0)
        for i, e in enumerate(self._queue):
            self._q_model.addRow([i + 1, e["method"], e["host"], e["path"], len(e["points"])])
        self._p_model.setRowCount(0); self._q_req_view.set_text("")
        self._set_queue_title()

    def _clear_q(self):
        self._queue = []
        self._q_model.setRowCount(0)
        self._p_model.setRowCount(0); self._q_req_view.set_text("")
        self._set_queue_title()

    def _refill_queue_table(self):
        """Redraw the queue from self._queue, renumbering as it goes."""
        self._q_model.setRowCount(0)
        for i, e in enumerate(self._queue):
            self._q_model.addRow([i + 1, e["method"], e["host"], e["path"],
                                  len(e["points"])])
        self._p_model.setRowCount(0); self._q_req_view.set_text("")
        self._set_queue_title()

    def _sort_queue_points(self):
        if not self._queue:
            return
        self._queue.sort(key=lambda e: (-len(e["points"]), e["host"], e["path"]))
        self._refill_queue_table()
        print("[Reflector v6] queue sorted by injection points (most first)")

    def _dedupe_queue(self):
        if not self._queue:
            return
        seen, keep = set(), []
        for e in self._queue:
            sig = self._endpoint_sig(e, True)
            if sig in seen:
                continue
            seen.add(sig)
            keep.append(e)
        gone = len(self._queue) - len(keep)
        self._queue = keep
        self._refill_queue_table()
        print("[Reflector v6] de-duplicated queue: %d removed, %d left"
              % (gone, len(self._queue)))

    def _reset_findings_ui(self):
        self._f_model.setRowCount(0)
        self._f_req_view.set_text(""); self._f_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._findings_tab, "  Findings  ")
        except Exception:
            pass

    def _clear_r(self):
        self._r_model.setRowCount(0); self._rstored = {}; self._kept = 0
        self._n_all = self._n_body = self._n_hdr = 0
        self._set_view_titles()
        self._req_view.set_text(""); self._resp_view.set_text("")
        self._ctx_area.setText("")
        self._prog.setValue(0); self._prog.setString("Idle")

    def _send_repeater(self):
        table = self._active_table()
        r = table.getSelectedRow()
        if r < 0:
            return
        mr = table.convertRowIndexToModel(r)
        n  = self._r_model.getValueAt(mr, 0)
        data = self._rstored.get(int(str(n)))
        if not data:
            return
        svc, modified = data["svc"], data["bytes"]
        if svc is None or modified is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", modified, None)
        except Exception as ex:
            print("[Reflector v6] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # ITab / state
    # -----------------------------------------------------------------------
    def getTabCaption(self):  return "Reflector v6"
    def getUiComponent(self): return self._root

    def extensionUnloaded(self):
        self._scan = False
        self._xscan = False
        self._cscan = False
        print("[Reflector v6] Unloaded.")
