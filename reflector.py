# -*- coding: utf-8 -*-
# Reflector - Burp Suite Extension (active reflection tester)
# Install: Extender > Extensions > Add > Type: Python > Select this file
# Requires: Jython standalone JAR configured in Extender > Options > Python Environment
#
# Right-click request(s) in the Site map / Proxy > Send to Reflector. It injects
# the canary "xssezwin" into each URL/body parameter and the path, one by one,
# sends them (rate-limited to 5 req/s max), and reports which ones reflect the
# canary in the response. Use Send to Repeater to probe a hit manually.

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

CANARY = "xssezwin"
MAX_RPS = 5.0

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
        DefaultTableModel.__init__(self, ["#", "Method", "Host", "Path", "Points"], 0)
    def isCellEditable(self, r, c): return False

class ResultModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Method", "Request", "Type", "Parameter", "Reflected", "Count", "Context"], 0)
    def isCellEditable(self, r, c): return False

class NumComparator(Comparator):
    def compare(self, a, b):
        return cmp(self._f(a), self._f(b))
    def _f(self, v):
        try:
            return float(str(v).strip())
        except Exception:
            return float("-inf")

class ResultRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr = table.convertRowIndexToModel(row)
        refl = str(table.getModel().getValueAt(mr, 5) or "")
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif refl == "YES":
            c.setBackground(Color(40, 60, 40)); c.setForeground(GREEN)
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
    def __init__(self, ext): self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._r_table.getSelectedRow()
            if r >= 0:
                self._e._show_result(r)

# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb    = callbacks
        self._h     = callbacks.getHelpers()
        self._queue = []        # dicts: {raw, svc, method, host, path, points}
        self._rstored = {}      # result# -> (req_str, resp_str, svc, bytes)
        self._rseq  = 1
        self._scan  = False
        self._lock  = threading.Lock()

        callbacks.setExtensionName("Reflector")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        if SwingUtilities.isEventDispatchThread():
            self._build()
        else:
            SwingUtilities.invokeAndWait(lambda: self._build())
        print("[Reflector] Loaded — right-click requests in Site map > Send to Reflector.")

    # -----------------------------------------------------------------------
    # UI
    # -----------------------------------------------------------------------
    def _build(self):
        self._root = JPanel(BorderLayout(6, 6))
        self._root.setBackground(BG)
        self._root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # Controls
        bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        bar.setBackground(BG)
        bar.add(mk_lbl("Canary:", 12, True))
        bar.add(mk_lbl(CANARY, 12, color=ACCENT))
        bar.add(Box.createHorizontalStrut(8))
        self._btn_start = mk_btn("  Start  ", GREEN)
        self._btn_start.addActionListener(lambda e: self._start())
        bar.add(self._btn_start)
        self._btn_stop = mk_btn("  Stop  ", RED)
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(lambda e: self._stop())
        bar.add(self._btn_stop)
        bar.add(mk_lbl("Req/sec (max 5):"))
        self._f_rps = mk_field("5", 4)
        bar.add(self._f_rps)
        self._prog = JProgressBar(0, 100)
        self._prog.setStringPainted(True); self._prog.setString("Idle")
        self._prog.setPreferredSize(Dimension(220, 22))
        self._prog.setBackground(BG3); self._prog.setForeground(ACCENT)
        bar.add(self._prog)
        self._root.add(bar, BorderLayout.NORTH)

        # Queue (left)
        self._q_model = QueueModel()
        self._q_table = JTable(self._q_model)
        style_table(self._q_table)
        for i, w in enumerate([30, 54, 150, 220, 52]):
            self._q_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._q_table.getSelectionModel().addListSelectionListener(QueueRowSel(self))
        q_btns = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2)); q_btns.setBackground(BG2)
        b_rm = mk_btn("Remove", BG3, FG); b_rm.addActionListener(lambda e: self._remove_q())
        b_cl = mk_btn("Clear Queue", BG3, FG); b_cl.addActionListener(lambda e: self._clear_q())
        q_btns.add(b_rm); q_btns.add(b_cl)
        q_wrap = JPanel(BorderLayout()); q_wrap.setBackground(BG)
        q_wrap.add(mk_card("Queued Requests", self._q_table), BorderLayout.CENTER)
        q_wrap.add(q_btns, BorderLayout.SOUTH)

        # Results (right)
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

        self._r_model = ResultModel()
        self._r_table = JTable(self._r_model)
        style_table(self._r_table)
        self._sorter = TableRowSorter(self._r_model)
        self._sorter.setComparator(0, NumComparator())
        self._sorter.setComparator(6, NumComparator())
        self._r_table.setRowSorter(self._sorter)
        rend = ResultRenderer()
        for i in range(self._r_model.getColumnCount()):
            self._r_table.getColumnModel().getColumn(i).setCellRenderer(rend)
        for i, w in enumerate([34, 54, 150, 52, 120, 64, 48, 240]):
            self._r_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._r_table.getSelectionModel().addListSelectionListener(ResultRowSel(self))
        r_wrap = JPanel(BorderLayout()); r_wrap.setBackground(BG)
        r_wrap.add(r_top, BorderLayout.NORTH)
        r_wrap.add(mk_card("Reflections", self._r_table), BorderLayout.CENTER)

        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, q_wrap, r_wrap)
        top_split.setResizeWeight(0.34); top_split.setDividerSize(5); top_split.setBackground(BG)

        # Viewer
        self._req_view  = MessageView("Request")
        self._resp_view = MessageView("Response")
        rr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._req_view, self._resp_view)
        rr.setResizeWeight(0.5); rr.setDividerSize(4); rr.setBackground(BG)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, rr)
        split.setResizeWeight(0.5); split.setDividerSize(4); split.setBackground(BG)
        self._root.add(split, BorderLayout.CENTER)
        self._cb.addSuiteTab(self)

    # -----------------------------------------------------------------------
    # Context menu
    # -----------------------------------------------------------------------
    def createMenuItems(self, inv):
        item = JMenuItem("Send to Reflector")
        item.addActionListener(lambda e: self._recv(inv))
        lst = ArrayList(); lst.add(item)
        return lst

    def _recv(self, inv):
        msgs = inv.getSelectedMessages()
        if not msgs:
            return
        added = 0
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
                points = self._parse_points(raw)
                self._queue.append({"raw": raw, "svc": svc, "method": method,
                                    "host": host, "path": path, "points": points})
                self._q_model.addRow([len(self._queue), method, host, path, len(points)])
                added += 1
            except Exception as ex:
                print("[Reflector] load error: %s" % ex)
        if added:
            print("[Reflector] queued %d request(s)" % added)

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

        # Path (tested by appending the canary as a new segment)
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

    def _inject(self, raw, item, value):
        reqline, headers, body, sep = self._split_req(raw)
        kind = item["kind"]
        if kind == "path":
            parts = reqline.split(" ")
            path, q, query = parts[1].partition("?")
            newpath = path.rstrip("/") + "/" + value
            parts[1] = newpath + (("?" + query) if q else "")
            reqline = " ".join(parts)
        elif kind == "url":
            parts = reqline.split(" ")
            path, q, query = parts[1].partition("?")
            pairs = self._set_pair(self._pairs(query), item["name"], value)
            parts[1] = path + ("?" + self._rebuild_qs(pairs) if pairs else "")
            reqline = " ".join(parts)
        elif kind == "body":
            pairs = self._set_pair(self._pairs(body.strip()), item["name"], value)
            body = self._rebuild_qs(pairs)
        elif kind == "json":
            body = self._set_json(body, item.get("path", [item["name"]]), value)
        headers = self._fix_cl(headers, body)
        return self._h.stringToBytes(self._join_req(reqline, headers, body, sep))

    # -----------------------------------------------------------------------
    # Scan (single worker, rate-limited to <= 5 req/s)
    # -----------------------------------------------------------------------
    def _start(self):
        if self._scan:
            return
        if not self._queue:
            self._prog.setString("Queue empty"); return
        try:
            rps = float(self._f_rps.getText().strip() or "5")
        except Exception:
            rps = 5.0
        rps = max(0.2, min(MAX_RPS, rps))
        self._f_rps.setText(str(int(rps)) if rps == int(rps) else str(rps))
        self._scan = True
        self._btn_start.setEnabled(False); self._btn_stop.setEnabled(True)
        t = threading.Thread(target=self._worker, args=(list(self._queue), 1.0 / rps))
        t.setDaemon(True); t.start()

    def _stop(self):
        self._scan = False

    def _worker(self, snapshot, interval):
        try:
            total = sum(len(e["points"]) for e in snapshot)
            done = 0
            self._rstored = {}; self._rseq = 1
            SwingUtilities.invokeLater(lambda: self._r_model.setRowCount(0))
            for entry in snapshot:
                for it in entry["points"]:
                    if not self._scan:
                        break
                    t0 = time.time()
                    try:
                        modified = self._inject(entry["raw"], it, CANARY)
                        resp = self._cb.makeHttpRequest(entry["svc"], modified)
                        rb   = resp.getResponse()
                        rs   = self._h.bytesToString(rb) if rb else ""
                        reqs = self._h.bytesToString(modified)
                        cnt  = rs.lower().count(CANARY)
                        refl = "YES" if cnt > 0 else "no"
                        snippet = ""
                        if cnt > 0:
                            idx = rs.lower().find(CANARY)
                            s = max(0, idx - 20); e = min(len(rs), idx + len(CANARY) + 20)
                            snippet = rs[s:e].replace("\r", " ").replace("\n", " ")
                        rid = self._rseq; self._rseq += 1
                        self._rstored[rid] = (reqs, rs, entry["svc"], modified)
                        row = [rid, entry["method"], entry["path"],
                               KIND_LABEL.get(it["kind"], it["kind"]), it["name"],
                               refl, cnt, snippet]
                        done += 1
                        pct = int(done * 100.0 / total) if total else 100
                        SwingUtilities.invokeLater(
                            lambda r=row, p=pct, d=done, tt=total:
                                self._add_result(r, p, "%d / %d" % (d, tt)))
                    except Exception as ex:
                        print("[Reflector] request error: %s" % ex)
                        done += 1
                    # rate limit: keep >= interval between request starts
                    rem = interval - (time.time() - t0)
                    if rem > 0:
                        time.sleep(rem)
                if not self._scan:
                    break
        except Exception as ex:
            print("[Reflector] worker error: %s" % ex)
        finally:
            self._scan = False
            SwingUtilities.invokeLater(self._done)

    def _add_result(self, row, pct, label):
        self._r_model.addRow(row)
        self._prog.setValue(pct); self._prog.setString(label)

    def _done(self):
        self._btn_start.setEnabled(True); self._btn_stop.setEnabled(False)
        self._prog.setValue(100)
        hits = sum(1 for i in range(self._r_model.getRowCount())
                   if str(self._r_model.getValueAt(i, 5)) == "YES")
        self._prog.setString("Done - %d reflected" % hits)

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
            filters = ArrayList()
            if self._rb_get.isSelected():
                filters.add(RowFilter.regexFilter("(?i)^GET$", 1))
            elif self._rb_write.isSelected():
                filters.add(RowFilter.regexFilter("(?i)^(POST|PUT|PATCH)$", 1))
            if self._tg_refl.isSelected():
                filters.add(RowFilter.regexFilter("^YES$", 5))
            if filters.size() > 0:
                self._sorter.setRowFilter(RowFilter.andFilter(filters))
            else:
                self._sorter.setRowFilter(None)
        except Exception as ex:
            print("[Reflector] filter error: %s" % ex)

    def _show_queue(self, view_row):
        if 0 <= view_row < len(self._queue):
            self._req_view.set_text(self._queue[view_row]["raw"])
            self._resp_view.set_text("")

    def _show_result(self, view_row):
        mr = self._r_table.convertRowIndexToModel(view_row)
        n  = self._r_model.getValueAt(mr, 0)
        data = self._rstored.get(int(str(n)))
        if data:
            self._req_view.set_text(data[0])
            self._resp_view.set_text(data[1])
            self._resp_view.search_for(CANARY)

    def _remove_q(self):
        rows = sorted(set(self._q_table.getSelectedRows()), reverse=True)
        for r in rows:
            if 0 <= r < len(self._queue):
                del self._queue[r]
        self._q_model.setRowCount(0)
        for i, e in enumerate(self._queue):
            self._q_model.addRow([i + 1, e["method"], e["host"], e["path"], len(e["points"])])

    def _clear_q(self):
        self._queue = []
        self._q_model.setRowCount(0)

    def _clear_r(self):
        self._r_model.setRowCount(0); self._rstored = {}
        self._req_view.set_text(""); self._resp_view.set_text("")
        self._prog.setValue(0); self._prog.setString("Idle")

    def _send_repeater(self):
        r = self._r_table.getSelectedRow()
        if r < 0:
            return
        mr = self._r_table.convertRowIndexToModel(r)
        n  = self._r_model.getValueAt(mr, 0)
        data = self._rstored.get(int(str(n)))
        if not data:
            return
        req_str, resp_str, svc, modified = data
        if svc is None or modified is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", modified, None)
        except Exception as ex:
            print("[Reflector] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # ITab / state
    # -----------------------------------------------------------------------
    def getTabCaption(self):  return "Reflector"
    def getUiComponent(self): return self._root

    def extensionUnloaded(self):
        self._scan = False
        print("[Reflector] Unloaded.")
