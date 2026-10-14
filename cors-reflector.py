# -*- coding: utf-8 -*-
# CORS Reflector - Burp Suite Extension
# Install: Extender > Extensions > Add > Type: Python > Select this file
# Requires: Jython standalone JAR configured in Extender > Options > Python Environment
#
# Right-click request(s) in the Site map / Proxy > Send to CORS Reflector. Each
# queued request is replayed once per probe origin, with the Origin header
# match-replaced and nothing else touched. The replies are read for
# Access-Control-Allow-Origin / -Allow-Credentials / Vary, and anything that
# trusts an origin an attacker controls lands in the Findings tab.
#
# Rate limited to 5 requests/sec maximum (4/sec by default), one worker thread.

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField, JCheckBox,
    JTextArea, JSplitPane, JMenuItem, SwingUtilities, BorderFactory,
    JRadioButton, ButtonGroup, RowFilter, JTabbedPane, JProgressBar, Box,
    JToggleButton
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.text import DefaultHighlighter
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension
from java.util import ArrayList, Comparator
import threading
import time

MAX_RPS     = 5.0        # hard ceiling
DEFAULT_RPS = 4.0
EVIL        = "evil.com"

NOT_RETAINED = ("(response not retained - nothing of interest in it)\n\n"
                "Holding every probe's response put tens of MB of strings in Burp's heap. Tick \"Keep all responses\" before the run to hold on to "
                "every one, or use Send to Repeater to fetch this one again.")

# Characters browsers tolerate in a hostname that whitelist regexes routinely
# miss. "https://target.com_.evil.com" is a hostname the attacker owns, yet a
# naive  origin.startswith("https://target.com")  check waves it through.
SPECIAL_CHARS = ["_", "-", "+", "{", "}", "^", "%60", "!", "~", "*",
                 "'", "(", ")", ";", "&", "=", "$", ",", "|"]

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
# Probe origins
# ---------------------------------------------------------------------------
def parent_domain(host):
    """app.example.com -> example.com   (example.com -> example.com)"""
    bits = host.split(".")
    return ".".join(bits[1:]) if len(bits) > 2 else host


def origin_probes(host, scheme, evil=EVIL, specials=True):
    """[(technique, origin, kind)] for one target host.

    kind is what the result means if the origin comes back reflected:
      control    - the request's own origin; never a finding, just the control
      attacker   - an origin an attacker can actually serve from
      same-host  - still resolves to the target, so not attacker-controlled;
                   worth knowing about, capped at Low
    """
    other  = "http" if scheme == "https" else "https"
    parent = parent_domain(host)
    probes = [
        ("same-origin control", "%s://%s" % (scheme, host),        "control"),
        ("arbitrary origin",    "https://%s" % evil,               "attacker"),
        ("null origin",         "null",                            "attacker"),
        ("suffix match",        "https://not%s" % host,            "attacker"),
        ("parent suffix match", "https://not%s" % parent,          "attacker"),
        ("prefix match",        "https://%s.%s" % (host, evil),    "attacker"),
        ("subdomain trust",     "https://evil.%s" % host,          "attacker"),
        ("localhost",           "http://localhost",                "attacker"),
        ("loopback",            "http://127.0.0.1",                "attacker"),
        ("scheme downgrade",    "%s://%s" % (other, host),         "same-host"),
        ("trailing dot",        "%s://%s." % (scheme, host),       "same-host"),
        ("upper case",          "%s://%s" % (scheme, host.upper()), "same-host"),
    ]
    if specials:
        for ch in SPECIAL_CHARS:
            probes.append(("special char  %s" % ch,
                           "https://%s%s.%s" % (host, ch, evil), "attacker"))

    seen, out = set(), []
    for t, o, k in probes:
        if o in seen:
            continue
        seen.add(o)
        out.append((t, o, k))
    return out


# What a reflected origin means.  Returns (verdict, severity, why) or None.
def classify(sent, acao, acac, kind):
    a  = (acao or "").strip()
    al = a.lower()
    s  = (sent or "").strip()
    creds = (acac or "").strip().lower() == "true"
    if not a or kind == "control":
        return None

    if al == "*":
        if creds:
            return ("wildcard + credentials", "Low",
                    "ACAO: * sent alongside Allow-Credentials: true - browsers "
                    "refuse that pair, so this is a misconfiguration rather than "
                    "a read primitive")
        return ("wildcard", "Low",
                "ACAO: * - any site can read this response, but without cookies "
                "or auth headers")

    if al == "null" and s.lower() == "null":
        if creds:
            return ("null + credentials", "High",
                    "The null origin is trusted with credentials. A sandboxed "
                    "iframe or a data: URL sends Origin: null, so any site can "
                    "read authenticated responses from this endpoint")
        return ("null origin", "Medium",
                "The null origin is trusted. Readable from a sandboxed iframe, "
                "but without credentials")

    if al == s.lower():
        if kind == "same-host":
            return ("reflected (same host)", "Low",
                    "The origin is reflected, but it still resolves to the "
                    "target itself - an attacker cannot serve from it. Worth "
                    "noting as loose origin handling, not a read primitive")
        if creds:
            return ("reflected + credentials", "High",
                    "The origin is reflected with Allow-Credentials: true - an "
                    "attacker-controlled page can read authenticated responses "
                    "from this endpoint")
        return ("reflected", "Medium",
                "The origin is reflected but credentials are not allowed - a "
                "cross-origin read of whatever this endpoint returns "
                "unauthenticated")
    return None


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
# Pretty printing
# ---------------------------------------------------------------------------
def pretty_message(raw):
    if not raw:
        return raw
    sep = "\r\n\r\n"; idx = raw.find(sep)
    if idx < 0:
        sep = "\n\n"; idx = raw.find(sep)
    if idx < 0:
        return raw
    return raw[:idx] + sep + _pretty_body(raw[idx + len(sep):])

def _pretty_body(body):
    b = body.strip()
    if not b:
        return body
    if b[0] in "{[":
        try:
            import json
            return json.dumps(json.loads(b), indent=2)
        except Exception:
            return body
    if b[0] == "<":
        try:
            import re
            x = re.sub(r">\s*<", ">\n<", b)
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
            return body
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
        self.area = JTextArea()
        self.area.setBackground(BG2); self.area.setForeground(FG)
        self.area.setCaretColor(FG); self.area.setEditable(False)
        self.area.setFont(Font("Courier New", Font.PLAIN, 12))
        self.area.setSelectionColor(ACCENT); self.area.setSelectedTextColor(Color.WHITE)
        self._painter = DefaultHighlighter.DefaultHighlightPainter(Color(120, 100, 40))
        sc = JScrollPane(self.area)
        sc.getViewport().setBackground(BG2); sc.setBorder(None)
        self.add(sc, BorderLayout.CENTER)
        self.add(self._bar(), BorderLayout.SOUTH)

    def _bar(self):
        bar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        bar.setBackground(BG3)
        bar.add(mk_lbl("Find:", 11))
        self._sf = JTextField("", 16)
        self._sf.setBackground(BG2); self._sf.setForeground(FG); self._sf.setCaretColor(FG)
        self._sf.setFont(Font("Courier New", Font.PLAIN, 12))
        self._sf.getDocument().addDocumentListener(_MVSearchDoc(self))
        self._sf.addActionListener(lambda e: self.find_next())
        bar.add(self._sf)
        bp = mk_btn("  <  ", BG2, FG); bp.addActionListener(lambda e: self.find_prev())
        bn = mk_btn("  >  ", BG2, FG); bn.addActionListener(lambda e: self.find_next())
        bar.add(bp); bar.add(bn)
        self._count = mk_lbl("0/0", 11, color=FG_DIM)
        bar.add(self._count)
        self._pretty = JCheckBox("Pretty", True)
        self._pretty.setBackground(BG3); self._pretty.setForeground(FG)
        self._pretty.addActionListener(lambda e: self._render())
        bar.add(self._pretty)
        return bar

    def set_text(self, raw):
        self._raw = raw or ""
        self._render()

    def search_for(self, text):
        self._sf.setText(text or "")

    def _render(self):
        txt = pretty_message(self._raw) if self._pretty.isSelected() else self._raw
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
        DefaultTableModel.__init__(self, ["#", "Method", "Host", "Path", "Origin"], 0)
    def isCellEditable(self, r, c): return False

class ProbeModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Request", "Technique", "Origin sent", "Status",
             "Allow-Origin", "Creds", "Vary", "Verdict"], 0)
    def isCellEditable(self, r, c): return False

class FindingsModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Severity", "Request", "Technique", "Origin sent",
             "Allow-Origin", "Creds", "Hits", "Why"], 0)
    def isCellEditable(self, r, c): return False

class NumComparator(Comparator):
    def compare(self, a, b):
        return cmp(self._f(a), self._f(b))
    def _f(self, v):
        try:
            return float(str(v).strip())
        except Exception:
            return float("-inf")

class ProbeRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr = table.convertRowIndexToModel(row)
        verdict = str(table.getModel().getValueAt(mr, 8) or "")
        creds   = str(table.getModel().getValueAt(mr, 6) or "")
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif verdict and "credentials" in verdict:
            c.setBackground(Color(70, 35, 35)); c.setForeground(Color(255, 120, 120))
        elif verdict in ("reflected", "null origin"):
            c.setBackground(Color(70, 60, 30)); c.setForeground(YELLOW)
        elif verdict and verdict != "-":
            c.setBackground(Color(38, 48, 58)); c.setForeground(Color(150, 185, 215))
        else:
            c.setBackground(BG2); c.setForeground(FG_DIM)
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c

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
        elif sev == "Low":
            c.setBackground(Color(38, 48, 58)); c.setForeground(Color(150, 185, 215))
        else:
            c.setBackground(BG2); c.setForeground(FG)
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

class ProbeRowSel(ListSelectionListener):
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._p_table.getSelectedRow()
            if r >= 0:
                self._e._show_probe(r)

class FindingRowSel(ListSelectionListener):
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._f_table.getSelectedRow()
            if r >= 0:
                self._e._show_finding(r)


# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb    = callbacks
        self._h     = callbacks.getHelpers()
        self._queue = []        # {raw, svc, method, host, path, scheme, origin}
        self._pstored = {}      # probe#   -> (req_str, resp_str|None, svc, bytes)
        self._kept    = 0       # bytes of response text held for the viewer
        self._fstored = {}      # finding# -> (req_str, resp_str, svc, bytes)
        self._pseq  = 1
        self._fseq  = 1
        self._fseen = {}        # (path, verdict) -> finding#
        self._fhits = {}
        self._scan  = False
        self._lock  = threading.Lock()

        callbacks.setExtensionName("CORS Reflector")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        if SwingUtilities.isEventDispatchThread():
            self._build()
        else:
            SwingUtilities.invokeAndWait(lambda: self._build())
        print("[CORS Reflector] Loaded - right-click requests in Site map > "
              "Send to CORS Reflector.")

    # -----------------------------------------------------------------------
    # UI
    # -----------------------------------------------------------------------
    def _build(self):
        probe_panel = JPanel(BorderLayout(6, 6))
        probe_panel.setBackground(BG)
        probe_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # Controls
        bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        bar.setBackground(BG)
        bar.add(mk_lbl("Attacker domain:", 12, True))
        self._f_evil = mk_field(EVIL, 14)
        self._f_evil.setToolTipText(
            "Used to build the attacker-controlled probe origins: "
            "https://<domain>, https://target<char>.<domain>, "
            "https://target.<domain>")
        bar.add(self._f_evil)
        self._ck_keep = mk_check("Keep all responses", False)
        self._ck_keep.setToolTipText(
            "Off (recommended): only responses that actually sent an "
            "Access-Control-Allow-Origin header are held for the viewer - "
            "findings are always kept. On: every probe is retained.")
        bar.add(self._ck_keep)
        self._ck_specials = mk_check("Special-char bypasses", True)
        self._ck_specials.setToolTipText(
            "Adds %d origins of the form https://target.com_.evil.com - "
            "hostnames the attacker owns that a sloppy prefix check accepts. "
            "Costs %d extra requests per queued request."
            % (len(SPECIAL_CHARS), len(SPECIAL_CHARS)))
        self._ck_specials.addActionListener(lambda e: self._recount())
        bar.add(self._ck_specials)
        bar.add(Box.createHorizontalStrut(8))
        self._btn_start = mk_btn("  Start  ", GREEN)
        self._btn_start.addActionListener(lambda e: self._start())
        bar.add(self._btn_start)
        self._btn_stop = mk_btn("  Stop  ", RED)
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(lambda e: self._stop())
        bar.add(self._btn_stop)
        bar.add(mk_lbl("Req/sec (max %d):" % int(MAX_RPS)))
        self._f_rps = mk_field(str(int(DEFAULT_RPS)), 4)
        bar.add(self._f_rps)
        self._prog = JProgressBar(0, 100)
        self._prog.setStringPainted(True); self._prog.setString("Idle")
        self._prog.setPreferredSize(Dimension(220, 22))
        self._prog.setBackground(BG3); self._prog.setForeground(ACCENT)
        bar.add(self._prog)
        probe_panel.add(bar, BorderLayout.NORTH)

        # Queue (left)
        self._q_model = QueueModel()
        self._q_table = JTable(self._q_model)
        style_table(self._q_table)
        for i, w in enumerate([30, 54, 140, 190, 150]):
            self._q_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._q_table.getSelectionModel().addListSelectionListener(QueueRowSel(self))
        q_btns = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2)); q_btns.setBackground(BG2)
        b_rm = mk_btn("Remove", BG3, FG); b_rm.addActionListener(lambda e: self._remove_q())
        b_cl = mk_btn("Clear Queue", BG3, FG); b_cl.addActionListener(lambda e: self._clear_q())
        q_btns.add(b_rm); q_btns.add(b_cl)
        q_wrap = JPanel(BorderLayout()); q_wrap.setBackground(BG)
        q_wrap.add(mk_card("Queued Requests", self._q_table), BorderLayout.CENTER)
        q_wrap.add(q_btns, BorderLayout.SOUTH)

        # Probes (right)
        p_top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)); p_top.setBackground(BG)
        p_top.add(mk_lbl("Show:"))
        self._rb_all = mk_radio("All", True)
        self._rb_cors = mk_radio("CORS headers only")
        mg = ButtonGroup()
        for rb in (self._rb_all, self._rb_cors):
            mg.add(rb); rb.addActionListener(lambda e: self._apply_filters()); p_top.add(rb)
        self._tg_hit = JToggleButton("Verdicts Only")
        self._tg_hit.setBackground(BG3); self._tg_hit.setForeground(FG)
        self._tg_hit.setFocusPainted(False); self._tg_hit.setBorderPainted(False)
        self._tg_hit.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._tg_hit.addActionListener(lambda e: self._toggle_hit())
        p_top.add(self._tg_hit)
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_repeater(
            self._p_table, self._p_model, self._pstored, "CORS"))
        p_top.add(b_rep)
        b_pc = mk_btn("Clear Probes", BG3, FG)
        b_pc.addActionListener(lambda e: self._clear_p())
        p_top.add(b_pc)

        self._p_model = ProbeModel()
        self._p_table = JTable(self._p_model)
        style_table(self._p_table)
        self._sorter = TableRowSorter(self._p_model)
        self._sorter.setComparator(0, NumComparator())
        self._sorter.setComparator(4, NumComparator())
        self._p_table.setRowSorter(self._sorter)
        prend = ProbeRenderer()
        for i in range(self._p_model.getColumnCount()):
            self._p_table.getColumnModel().getColumn(i).setCellRenderer(prend)
        for i, w in enumerate([34, 140, 120, 200, 50, 190, 48, 90, 150]):
            self._p_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._p_table.getSelectionModel().addListSelectionListener(ProbeRowSel(self))
        p_wrap = JPanel(BorderLayout()); p_wrap.setBackground(BG)
        p_wrap.add(p_top, BorderLayout.NORTH)
        p_wrap.add(mk_card("Origin Probes", self._p_table), BorderLayout.CENTER)

        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, q_wrap, p_wrap)
        top_split.setResizeWeight(0.30); top_split.setDividerSize(5); top_split.setBackground(BG)

        self._req_view  = MessageView("Request")
        self._resp_view = MessageView("Response")
        rr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._req_view, self._resp_view)
        rr.setResizeWeight(0.5); rr.setDividerSize(4); rr.setBackground(BG)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, rr)
        split.setResizeWeight(0.5); split.setDividerSize(4); split.setBackground(BG)
        probe_panel.add(split, BorderLayout.CENTER)

        self._tabs = JTabbedPane()
        self._tabs.setBackground(BG); self._tabs.setForeground(FG)
        self._tabs.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._tabs.addTab("  Probes  ", probe_panel)
        self._tabs.addTab("  Findings  ", self._build_findings())
        self._findings_tab = 1

        self._root = JPanel(BorderLayout())
        self._root.setBackground(BG)
        self._root.add(self._tabs)
        self._cb.addSuiteTab(self)

    def _build_findings(self):
        p = JPanel(BorderLayout(6, 6))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        top.setBackground(BG)
        top.add(mk_lbl("Origins this endpoint trusts  -  High means an "
                       "attacker-controlled origin is reflected with credentials",
                       11, color=FG_DIM))
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_repeater(
            self._f_table, self._f_model, self._fstored, "CORS finding"))
        top.add(b_rep)
        b_cl = mk_btn("Clear", BG3, FG)
        b_cl.addActionListener(lambda e: self._clear_f())
        top.add(b_cl)
        p.add(top, BorderLayout.NORTH)

        self._f_model = FindingsModel()
        self._f_table = JTable(self._f_model)
        style_table(self._f_table)
        fs = TableRowSorter(self._f_model)
        fs.setComparator(0, NumComparator())
        fs.setComparator(7, NumComparator())
        self._f_table.setRowSorter(fs)
        frend = FindingsRenderer()
        for i in range(self._f_model.getColumnCount()):
            self._f_table.getColumnModel().getColumn(i).setCellRenderer(frend)
        for i, w in enumerate([34, 62, 140, 120, 200, 190, 48, 40, 420]):
            self._f_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._f_table.getSelectionModel().addListSelectionListener(FindingRowSel(self))

        self._f_req_view  = MessageView("Request  (modified Origin)")
        self._f_resp_view = MessageView("Response")
        fr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._f_req_view, self._f_resp_view)
        fr.setResizeWeight(0.5); fr.setDividerSize(4); fr.setBackground(BG)

        fsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                            mk_card("Findings", self._f_table), fr)
        fsplit.setResizeWeight(0.45); fsplit.setDividerSize(4); fsplit.setBackground(BG)
        p.add(fsplit, BorderLayout.CENTER)
        return p

    # -----------------------------------------------------------------------
    # Context menu
    # -----------------------------------------------------------------------
    def createMenuItems(self, inv):
        item = JMenuItem("Send to CORS Reflector")
        item.addActionListener(lambda e: self._recv(inv))
        lst = ArrayList(); lst.add(item)
        return lst

    def _recv(self, inv):
        msgs = inv.getSelectedMessages()
        if not msgs:
            return
        added, skipped = 0, 0
        existing = set((e["method"], e["host"], e["path"]) for e in self._queue)
        for msg in msgs:
            try:
                req = msg.getRequest(); svc = msg.getHttpService()
                if req is None or svc is None:
                    continue
                raw = self._h.bytesToString(req)
                reqline, headers, body, sep = self._split_req(raw)
                parts  = reqline.split(" ")
                method = parts[0] if parts else "?"
                target = parts[1] if len(parts) > 1 else "/"
                path   = target.split("?", 1)[0]
                host   = str(svc.getHost())
                try:
                    scheme = "https" if svc.getProtocol() == "https" else "http"
                except Exception:
                    scheme = "https"
                sig = (method, host, path)
                if sig in existing:
                    skipped += 1
                    continue
                existing.add(sig)
                self._queue.append({"raw": raw, "svc": svc, "method": method,
                                    "host": host, "path": path, "scheme": scheme,
                                    "origin": self._header(headers, "Origin")})
                added += 1
            except Exception as ex:
                print("[CORS Reflector] load error: %s" % ex)
        if added:
            self._refresh_queue()
            print("[CORS Reflector] queued %d request(s)%s" %
                  (added, (", %d duplicate(s) skipped" % skipped) if skipped else ""))

    def _refresh_queue(self):
        self._q_model.setRowCount(0)
        for i, e in enumerate(self._queue):
            self._q_model.addRow([i + 1, e["method"], e["host"], e["path"],
                                  e["origin"] or "(none sent)"])

    def _recount(self):
        n = self._probe_count()
        if self._queue:
            self._prog.setString("%d request(s) x %d origins" % (len(self._queue), n))

    def _probe_count(self):
        return len(origin_probes("a.example.com", "https",
                                 specials=self._ck_specials.isSelected()))

    # -----------------------------------------------------------------------
    # Request helpers
    # -----------------------------------------------------------------------
    def _split_req(self, raw):
        head, sep, body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        return lines[0], lines[1:], body, (sep if sep else "\r\n\r\n")

    def _join_req(self, reqline, headers, body, sep):
        return "\r\n".join([reqline] + headers) + sep + body

    def _header(self, headers, name):
        pre = name.lower() + ":"
        for hl in headers:
            if hl.lower().startswith(pre):
                return hl.split(":", 1)[1].strip()
        return ""

    def _set_header(self, headers, name, value):
        """Match-replace one header's value; append it if the request has none.
        Duplicates of the same header are dropped."""
        pre, out, done = name.lower() + ":", [], False
        for hl in headers:
            if hl.lower().startswith(pre):
                if not done:
                    out.append("%s: %s" % (name, value)); done = True
            else:
                out.append(hl)
        if not done:
            out.append("%s: %s" % (name, value))
        return out

    def _with_origin(self, raw, origin):
        """The queued request with Origin: <origin> and nothing else changed."""
        reqline, headers, body, sep = self._split_req(raw)
        headers = self._set_header(headers, "Origin", origin)
        return self._h.stringToBytes(self._join_req(reqline, headers, body, sep))

    # -----------------------------------------------------------------------
    # Response helpers
    # -----------------------------------------------------------------------
    def _resp_header(self, resp, name):
        if not resp:
            return ""
        head = resp.split("\r\n\r\n", 1)[0]
        pre  = name.lower() + ":"
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith(pre):
                return line.split(":", 1)[1].strip()
        return ""

    def _status(self, resp):
        if not resp:
            return "ERR"
        parts = resp.split("\r\n", 1)[0].split(" ")
        return parts[1] if len(parts) > 1 else "?"

    # -----------------------------------------------------------------------
    # Scan (single worker, rate-limited)
    # -----------------------------------------------------------------------
    def _start(self):
        if self._scan:
            return
        if not self._queue:
            self._prog.setString("Queue empty"); return
        try:
            rps = float(self._f_rps.getText().strip() or str(DEFAULT_RPS))
        except Exception:
            rps = DEFAULT_RPS
        rps = max(0.2, min(MAX_RPS, rps))
        self._f_rps.setText(str(int(rps)) if rps == int(rps) else str(rps))
        evil = self._f_evil.getText().strip() or EVIL
        specials = self._ck_specials.isSelected()
        self._scan = True
        self._btn_start.setEnabled(False); self._btn_stop.setEnabled(True)
        t = threading.Thread(target=self._worker,
                             args=(list(self._queue), 1.0 / rps, evil, specials))
        t.setDaemon(True); t.start()

    def _stop(self):
        self._scan = False

    def _worker(self, snapshot, interval, evil, specials):
        try:
            plans = []
            for entry in snapshot:
                probes = origin_probes(entry["host"], entry["scheme"], evil, specials)
                plans.append((entry, probes))
            total = sum(len(p) for _e, p in plans)
            done  = 0

            self._pstored = {}; self._pseq = 1
            self._fstored = {}; self._fseq = 1
            self._kept = 0
            keep_all = self._ck_keep.isSelected()
            self._fseen = {}; self._fhits = {}
            SwingUtilities.invokeLater(lambda: self._p_model.setRowCount(0))
            SwingUtilities.invokeLater(self._reset_findings_ui)
            print("[CORS Reflector] %d request(s) x origins = %d probe(s) at %.1f/s"
                  % (len(snapshot), total, (1.0 / interval) if interval > 0 else 0.0))

            for entry, probes in plans:
                if not self._scan:
                    break
                seen_acao = False
                for (tech, origin, kind) in probes:
                    if not self._scan:
                        break
                    t0 = time.time()
                    try:
                        modified = self._with_origin(entry["raw"], origin)
                        resp = self._cb.makeHttpRequest(entry["svc"], modified)
                        rb   = resp.getResponse()
                        rs   = self._h.bytesToString(rb) if rb else ""
                        reqs = self._h.bytesToString(modified)

                        acao   = self._resp_header(rs, "Access-Control-Allow-Origin")
                        acac   = self._resp_header(rs, "Access-Control-Allow-Credentials")
                        vary   = self._resp_header(rs, "Vary")
                        status = self._status(rs)
                        if acao:
                            seen_acao = True

                        res = classify(origin, acao, acac, kind)
                        verdict = res[0] if res else "-"

                        # Hold the response only when the server said something
                        # about CORS. The request is always kept - it is small and
                        # Send to Repeater needs it.
                        worth = bool(acao) or keep_all
                        with self._lock:
                            pid = self._pseq; self._pseq += 1
                            self._pstored[pid] = (reqs, rs if worth else None,
                                                  entry["svc"], modified)
                            if worth:
                                self._kept += len(rs)
                        row = [pid, entry["path"], tech, origin, status,
                               acao or "-", (acac or "-"), vary or "-", verdict]
                        done += 1
                        pct = int(done * 100.0 / total) if total else 100
                        SwingUtilities.invokeLater(
                            lambda r=row, p=pct, d=done, tt=total:
                                self._add_probe(r, p, "%d / %d" % (d, tt)))

                        if res:
                            self._add_finding(entry, tech, origin, acao, acac,
                                              vary, res, reqs, rs, modified)
                    except Exception as ex:
                        print("[CORS Reflector] request error: %s" % ex)
                        done += 1
                    rem = interval - (time.time() - t0)
                    if rem > 0:
                        time.sleep(rem)
                if not seen_acao:
                    print("[CORS Reflector] %s %s sent no Access-Control-Allow-Origin "
                          "for any probe - CORS is not enabled here"
                          % (entry["method"], entry["path"]))
        except Exception as ex:
            print("[CORS Reflector] worker error: %s" % ex)
        finally:
            self._scan = False
            SwingUtilities.invokeLater(self._done)

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------
    def _add_finding(self, entry, tech, origin, acao, acac, vary, res,
                     req_str, resp_str, modified):
        verdict, sev, why = res
        if ("reflect" in verdict or "null" in verdict) and "origin" not in (vary or "").lower():
            why += ". Vary does not list Origin, so a shared cache may serve this "\
                   "response to other origins"
        key = (entry["path"], verdict)
        with self._lock:
            # Once an attacker-controlled origin is known to be reflected, the
            # same-host variants (scheme downgrade, trailing dot, upper case)
            # add nothing - they reflect for the same reason.
            if verdict == "reflected (same host)":
                for stronger in ("reflected + credentials", "reflected"):
                    if (entry["path"], stronger) in self._fseen:
                        return
            if key in self._fseen:
                fid = self._fseen[key]
                self._fhits[fid] = self._fhits.get(fid, 1) + 1
                hits = self._fhits[fid]
                SwingUtilities.invokeLater(lambda: self._bump_hits(fid, hits))
                return
            fid = self._fseq; self._fseq += 1
            self._fseen[key] = fid
            self._fhits[fid] = 1
            self._fstored[fid] = (req_str, resp_str, entry["svc"], modified)
        row = [fid, sev, entry["path"], tech, origin, acao or "-", acac or "-", 1, why]
        SwingUtilities.invokeLater(lambda: self._add_finding_row(row))

    def _add_finding_row(self, row):
        self._f_model.addRow(row)
        try:
            self._tabs.setTitleAt(self._findings_tab,
                                  "  Findings (%d)  " % self._f_model.getRowCount())
        except Exception:
            pass

    def _bump_hits(self, fid, hits):
        for i in range(self._f_model.getRowCount()):
            if str(self._f_model.getValueAt(i, 0)) == str(fid):
                self._f_model.setValueAt(hits, i, 7)
                return

    def _reset_findings_ui(self):
        self._f_model.setRowCount(0)
        self._f_req_view.set_text(""); self._f_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._findings_tab, "  Findings  ")
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Display / queue management
    # -----------------------------------------------------------------------
    def _add_probe(self, row, pct, label):
        self._p_model.addRow(row)
        self._prog.setValue(pct); self._prog.setString(label)

    def _done(self):
        self._btn_start.setEnabled(True); self._btn_stop.setEnabled(False)
        self._prog.setValue(100)
        nf = self._f_model.getRowCount()
        high = sum(1 for i in range(nf)
                   if str(self._f_model.getValueAt(i, 1)) == "High")
        self._prog.setString("Done - %d finding(s)%s, %.1f MB kept"
                             % (nf, (", %d High" % high) if high else "",
                                self._kept / 1048576.0))

    def _toggle_hit(self):
        if self._tg_hit.isSelected():
            self._tg_hit.setBackground(GREEN); self._tg_hit.setForeground(Color.WHITE)
        else:
            self._tg_hit.setBackground(BG3); self._tg_hit.setForeground(FG)
        self._apply_filters()

    def _apply_filters(self):
        try:
            filters = ArrayList()
            if self._rb_cors.isSelected():
                filters.add(RowFilter.notFilter(RowFilter.regexFilter("^-$", 5)))
            if self._tg_hit.isSelected():
                filters.add(RowFilter.notFilter(RowFilter.regexFilter("^-$", 8)))
            if filters.size() > 0:
                self._sorter.setRowFilter(RowFilter.andFilter(filters))
            else:
                self._sorter.setRowFilter(None)
        except Exception as ex:
            print("[CORS Reflector] filter error: %s" % ex)

    def _show_queue(self, view_row):
        if 0 <= view_row < len(self._queue):
            self._req_view.set_text(self._queue[view_row]["raw"])
            self._resp_view.set_text("")

    def _show_probe(self, view_row):
        mr = self._p_table.convertRowIndexToModel(view_row)
        data = self._pstored.get(int(str(self._p_model.getValueAt(mr, 0))))
        if data:
            self._req_view.set_text(data[0])
            self._resp_view.set_text(data[1] if data[1] is not None else NOT_RETAINED)
            if data[1] is not None:
                self._resp_view.search_for("Access-Control-Allow-Origin")

    def _show_finding(self, view_row):
        mr = self._f_table.convertRowIndexToModel(view_row)
        data = self._fstored.get(int(str(self._f_model.getValueAt(mr, 0))))
        if data:
            self._f_req_view.set_text(data[0])
            self._f_resp_view.set_text(data[1])
            self._f_resp_view.search_for("Access-Control-Allow-Origin")

    def _remove_q(self):
        for r in sorted(set(self._q_table.getSelectedRows()), reverse=True):
            if 0 <= r < len(self._queue):
                del self._queue[r]
        self._refresh_queue()

    def _clear_q(self):
        self._queue = []
        self._q_model.setRowCount(0)
        self._req_view.set_text(""); self._resp_view.set_text("")

    def _clear_p(self):
        self._p_model.setRowCount(0); self._pstored = {}; self._kept = 0
        self._req_view.set_text(""); self._resp_view.set_text("")
        self._prog.setValue(0); self._prog.setString("Idle")

    def _clear_f(self):
        self._f_model.setRowCount(0); self._fstored = {}
        self._fseen = {}; self._fhits = {}; self._fseq = 1
        self._f_req_view.set_text(""); self._f_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._findings_tab, "  Findings  ")
        except Exception:
            pass

    def _send_repeater(self, table, model, stored, tag):
        r = table.getSelectedRow()
        if r < 0:
            return
        mr = table.convertRowIndexToModel(r)
        n  = model.getValueAt(mr, 0)
        data = stored.get(int(str(n)))
        if not data:
            return
        req_str, resp_str, svc, modified = data
        if svc is None or modified is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", modified,
                                    "%s %s" % (tag, n))
        except Exception as ex:
            print("[CORS Reflector] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # ITab / state
    # -----------------------------------------------------------------------
    def getTabCaption(self):  return "CORS Reflector"
    def getUiComponent(self): return self._root

    def extensionUnloaded(self):
        self._scan = False
        print("[CORS Reflector] Unloaded.")
