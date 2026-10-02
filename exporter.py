# -*- coding: utf-8 -*-
# Sitemap Keeper - Burp Suite extension (Jython 2.7)
# Export / import the Site map together with highlight colours and comments,
# so you can keep track of what you've already tested between sessions.

from burp import IBurpExtender, ITab, IHttpRequestResponse
from javax.swing import (JPanel, JButton, JLabel, JTextField, JCheckBox,
                         JTextArea, JScrollPane, JFileChooser, SwingUtilities,
                         BoxLayout, Box)
from java.awt import BorderLayout, FlowLayout
from java.lang import Thread, Runnable
import json
import io

FORMAT_VERSION = 1


class StoredItem(IHttpRequestResponse):
    """Minimal IHttpRequestResponse used to push items back into the site map."""

    def __init__(self, request, response, service, comment, highlight):
        self._req = request
        self._resp = response
        self._svc = service
        self._comment = comment
        self._highlight = highlight

    def getRequest(self):
        return self._req

    def setRequest(self, m):
        self._req = m

    def getResponse(self):
        return self._resp

    def setResponse(self, m):
        self._resp = m

    def getComment(self):
        return self._comment

    def setComment(self, c):
        self._comment = c

    def getHighlight(self):
        return self._highlight

    def setHighlight(self, c):
        self._highlight = c

    def getHttpService(self):
        return self._svc

    def setHttpService(self, s):
        self._svc = s


class Task(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sitemap Keeper")
        self._build_ui()
        callbacks.addSuiteTab(self)
        self.log("Sitemap Keeper loaded.")

    # ---------------------------------------------------------------- UI
    def _build_ui(self):
        self.panel = JPanel(BorderLayout(10, 10))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(JLabel("URL prefix filter (blank = whole site map):"))
        self.prefix = JTextField(35)
        row1.add(self.prefix)
        top.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        self.only_marked = JCheckBox(
            "Export only highlighted / commented items", False)
        row2.add(self.only_marked)
        top.add(row2)

        row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        b_exp = JButton("Export site map...", actionPerformed=self.on_export)
        b_imp = JButton("Import site map...", actionPerformed=self.on_import)
        row3.add(b_exp)
        row3.add(b_imp)
        top.add(row3)

        self.out = JTextArea(14, 60)
        self.out.setEditable(False)

        self.panel.add(top, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.out), BorderLayout.CENTER)

    def getTabCaption(self):
        return "Sitemap Keeper"

    def getUiComponent(self):
        return self.panel

    def log(self, msg):
        def f():
            self.out.append(msg + "\n")
            self.out.setCaretPosition(self.out.getDocument().getLength())
        SwingUtilities.invokeLater(Task(f))

    def _choose(self, save):
        fc = JFileChooser()
        if save:
            ok = fc.showSaveDialog(self.panel)
        else:
            ok = fc.showOpenDialog(self.panel)
        if ok != JFileChooser.APPROVE_OPTION:
            return None
        path = fc.getSelectedFile().getAbsolutePath()
        if save and not path.lower().endswith(".json"):
            path += ".json"
        return path

    # ----------------------------------------------------------- Export
    def on_export(self, event):
        path = self._choose(True)
        if not path:
            return
        prefix = self.prefix.getText().strip() or None
        only_marked = self.only_marked.isSelected()
        t = Thread(Task(lambda: self._export(path, prefix, only_marked)))
        t.start()

    def _proxy_marks(self):
        """Fallback lookup of highlight/comment from proxy history."""
        marks = {}
        try:
            for it in self.cb.getProxyHistory():
                h, c = it.getHighlight(), it.getComment()
                if h or c:
                    key = self._key(it)
                    if key:
                        marks[key] = (h, c)
        except Exception as e:
            self.log("Could not read proxy history marks: %s" % e)
        return marks

    def _key(self, item):
        try:
            ai = self.helpers.analyzeRequest(item)
            return ai.getMethod() + " " + ai.getUrl().toString()
        except Exception:
            return None

    def _export(self, path, prefix, only_marked):
        try:
            self.log("Exporting...")
            items = self.cb.getSiteMap(prefix)
            proxy_marks = self._proxy_marks()
            out = []
            marked = 0
            for it in items:
                req = it.getRequest()
                svc = it.getHttpService()
                if req is None or svc is None:
                    continue  # nothing to restore (e.g. folder-only nodes)
                highlight = it.getHighlight()
                comment = it.getComment()
                if not highlight and not comment:
                    h, c = proxy_marks.get(self._key(it), (None, None))
                    highlight, comment = h, c
                if highlight or comment:
                    marked += 1
                elif only_marked:
                    continue
                resp = it.getResponse()
                out.append({
                    "protocol": svc.getProtocol(),
                    "host": svc.getHost(),
                    "port": svc.getPort(),
                    "request": self.helpers.base64Encode(req),
                    "response": self.helpers.base64Encode(resp) if resp else None,
                    "highlight": highlight,
                    "comment": comment,
                })
            data = {"version": FORMAT_VERSION, "items": out}
            with io.open(path, "w", encoding="utf-8") as f:
                f.write(unicode(json.dumps(data)))
            self.log("Exported %d items (%d highlighted/commented) to %s"
                     % (len(out), marked, path))
        except Exception as e:
            self.log("EXPORT FAILED: %s" % e)

    # ----------------------------------------------------------- Import
    def on_import(self, event):
        path = self._choose(False)
        if not path:
            return
        t = Thread(Task(lambda: self._import(path)))
        t.start()

    def _import(self, path):
        try:
            self.log("Importing %s ..." % path)
            with io.open(path, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
            count = marked = failed = 0
            for d in data.get("items", []):
                try:
                    svc = self.helpers.buildHttpService(
                        d["host"], int(d["port"]), d["protocol"])
                    req = self.helpers.base64Decode(d["request"])
                    resp = d.get("response")
                    resp = self.helpers.base64Decode(resp) if resp else None
                    hl = d.get("highlight")
                    cm = d.get("comment")
                    # unicode -> str for Java String params
                    hl = str(hl) if hl else None
                    cm = cm.encode("utf-8") if cm else None
                    self.cb.addToSiteMap(StoredItem(req, resp, svc, cm, hl))
                    count += 1
                    if hl or cm:
                        marked += 1
                except Exception as e:
                    failed += 1
                    self.log("  skipped one item: %s" % e)
            self.log("Imported %d items (%d highlighted/commented), %d failed."
                     % (count, marked, failed))
        except Exception as e:
            self.log("IMPORT FAILED: %s" % e)
