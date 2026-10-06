# -*- coding: utf-8 -*-
#
# JS Asset Harvester  --  Burp Suite extension (Jython / legacy API)
#
# Right-click a host (or any request) in Sitemap or Proxy history ->
#   "JS Harvester: grab all JS / chunks / assets"
#
# Watch progress in the "JS Harvester" tab: live log, current activity, and a
# % progress bar. Stop button cancels and still exports what was collected.
#
# It sends everything through Burp (so your session cookies + session-handling
# rules apply), seeding from the host's sitemap, the selected request(s) and
# their captured responses, and the host root page; then parses <script src>,
# preload hints, literal .js refs, and webpack runtime chunk maps
# (__webpack_require__.p + chunkId->hash tables) to reconstruct lazy chunks,
# recursing over everything and exporting a .zip + _manifest.json.
#
# Install:
#   1. Extensions > Extensions settings > Python environment -> jython jar
#   2. Extensions > Add > Extension type: Python > this file
#
# Static collection only: it downloads assets; it does not attack anything.

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (JMenuItem, JFileChooser, JPanel, JLabel, JTextArea,
                         JScrollPane, JProgressBar, JButton, BoxLayout,
                         SwingUtilities, BorderFactory)
from java.awt import BorderLayout, FlowLayout, Dimension, Font
from java.net import URL
from java.io import File
from java.util import ArrayList
from threading import Thread, RLock, Event
import re
import json
import zipfile
import time

try:
    from urlparse import urljoin, urlparse   # Jython 2.7
except ImportError:
    from urllib.parse import urljoin, urlparse

try:
    from Queue import Queue, Empty            # Jython 2.7
except ImportError:
    from queue import Queue, Empty

EXT_NAME = "JS Asset Harvester"
TAB_NAME = "JS Harvester"
MAX_FILES = 3000
POLITE_DELAY = 0.03

# Number of concurrent fetch workers. Keeps at most this many requests in
# flight through Burp at once (politeness + avoids hammering the target).
MAX_CONCURRENCY = 4

# Per-request wall-clock timeout (seconds). Burp's own makeHttpRequest can
# block indefinitely when a host/CDN is unreachable or stalls; we run each
# fetch in a helper thread and give up on it after this long so one dead URL
# can never hang the whole harvest. The URL is recorded as a timeout and we
# move on.
FETCH_TIMEOUT = 20.0

# Extra hosts to treat as "part of this target" (e.g. its CDN / CloudFront
# distribution / S3 asset bucket). Hosts listed here are also seeded from the
# sitemap + proxy history, not just the primary host. Example:
#   RELATED_HOSTS = ["d2abc123.cloudfront.net", "static.example-cdn.com"]
# Cross-host JS that is *referenced* (script src / webpack publicPath) is always
# followed regardless of this list; RELATED_HOSTS only widens the SEEDING.
RELATED_HOSTS = []

# If True, your session cookies are also replayed to RELATED_HOSTS (needed only
# for private/authenticated CDN distributions). Leave False to avoid sending
# session tokens to any third-party host. Cookies are NEVER sent to hosts that
# are neither the primary host nor in RELATED_HOSTS.
SEND_COOKIES_TO_RELATED = False

# ---------------------------------------------------------------- regexes ----
RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RE_LINK = re.compile(
    r'<link[^>]+(?:rel=["\'](?:preload|modulepreload)["\'][^>]*href=["\']([^"\']+)["\']'
    r'|href=["\']([^"\']+)["\'][^>]*rel=["\'](?:preload|modulepreload)["\'])', re.I)
RE_JS_LITERAL = re.compile(r'["\'`]([^"\'`\s<>]+?\.(?:js|mjs))(?:\?[^"\'`\s<>]*)?["\'`]')

RE_PUBLIC_PATH = re.compile(r'(?:__webpack_require__\.p|\.p)\s*=\s*["\']([^"\']*)["\']')
RE_MAP = re.compile(r'\{((?:\s*["\']?[\w.@/-]+["\']?\s*:\s*["\'][\w.@/-]+["\']\s*,?){2,})\}')
RE_PREFIX_SUFFIX = re.compile(
    r'["\']([\w./-]*?)["\']\s*\+\s*[^+]*?\{[^{}]*\}[^+]*?\+\s*["\']([\w./-]*?)["\']')
RE_MAP_KV = re.compile(r'["\']?([\w.@/-]+)["\']?\s*:\s*["\']([\w.@/-]+)["\']')
RE_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=([^\s"\'<>]+)')


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    # -- lifecycle ------------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        self._running = False
        self._stop = False
        callbacks.setExtensionName(EXT_NAME)
        self._build_ui()
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.customizeUiComponent(self._panel)
        self._log("[*] %s loaded. Right-click a host in Sitemap/Proxy history, "
                  "then watch this tab." % EXT_NAME)

    # -- ITab -----------------------------------------------------------------
    def getTabCaption(self):
        return TAB_NAME

    def getUiComponent(self):
        return self._panel

    def _build_ui(self):
        self._panel = JPanel(BorderLayout())

        north = JPanel()
        north.setLayout(BoxLayout(north, BoxLayout.Y_AXIS))
        north.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        self._btn_stop = JButton("Stop", actionPerformed=lambda e: self._request_stop())
        self._btn_stop.setEnabled(False)
        self._btn_clear = JButton("Clear log", actionPerformed=lambda e: self._clear())
        toolbar.add(self._btn_stop)
        toolbar.add(self._btn_clear)

        self._status = JLabel("Idle. Right-click a host -> JS Harvester.")
        self._status.setFont(Font("SansSerif", Font.BOLD, 13))
        self._activity = JLabel(" ")
        self._activity.setForeground(self._status.getForeground())

        self._bar = JProgressBar(0, 100)
        self._bar.setStringPainted(True)
        self._bar.setString("idle")
        self._bar.setValue(0)
        self._bar.setPreferredSize(Dimension(400, 22))

        for c in (toolbar, self._status, self._bar, self._activity):
            c.setAlignmentX(JPanel.LEFT_ALIGNMENT)
            north.add(c)

        self._logArea = JTextArea()
        self._logArea.setEditable(False)
        self._logArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        scroll = JScrollPane(self._logArea)

        self._panel.add(north, BorderLayout.NORTH)
        self._panel.add(scroll, BorderLayout.CENTER)

    # -- UI helpers (always marshalled onto the EDT) --------------------------
    def _ui(self, fn):
        SwingUtilities.invokeLater(fn)

    def _log(self, msg):
        self._cb.printOutput(msg)
        def go():
            self._logArea.append(msg + "\n")
            self._logArea.setCaretPosition(self._logArea.getDocument().getLength())
        self._ui(go)

    def _clear(self):
        self._logArea.setText("")

    def _set_status(self, text):
        self._ui(lambda: self._status.setText(text))

    def _set_activity(self, text):
        t = text if len(text) < 110 else text[:107] + "..."
        self._ui(lambda: self._activity.setText(t))

    def _set_progress(self, done, remaining, saved):
        total = done + remaining
        pct = int(done * 100 / total) if total else 0
        def go():
            self._bar.setValue(pct)
            self._bar.setString("%d%%  (%d done, %d queued, %d saved)"
                                % (pct, done, remaining, saved))
        self._ui(go)

    def _finish_progress(self, saved, stopped):
        def go():
            self._bar.setValue(100 if not stopped else self._bar.getValue())
            self._bar.setString(("STOPPED" if stopped else "DONE")
                                + "  (%d saved)" % saved)
            self._btn_stop.setEnabled(False)
        self._ui(go)

    def _request_stop(self):
        if self._running:
            self._stop = True
            self._set_status("Stopping... will export what's collected.")

    # -- context menu ---------------------------------------------------------
    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        items = ArrayList()
        items.add(JMenuItem("JS Harvester: grab all JS / chunks / assets",
                            actionPerformed=lambda e, m=msgs: self._launch(m)))
        return items

    def _launch(self, msgs):
        if not msgs:
            self._log("[!] Nothing selected.")
            return
        if self._running:
            self._log("[!] A harvest is already running.")
            return
        Thread(target=self._harvest, args=(msgs,)).start()

    # -- core harvest ---------------------------------------------------------
    def _harvest(self, msgs):
        self._running = True
        self._stop = False
        self._ui(lambda: self._btn_stop.setEnabled(True))
        try:
            self._run(msgs)
        except Exception as ex:
            self._log("[!] Harvest error: %s" % ex)
            self._set_status("Error: %s" % ex)
        finally:
            self._running = False

    def _run(self, msgs):
        h = self._helpers
        seed_msg = msgs[0]
        svc = seed_msg.getHttpService()
        host = svc.getHost()
        scheme = "https" if svc.getProtocol() == "https" else "http"
        base_root = "%s://%s/" % (scheme, host)
        tmpl = self._header_template(seed_msg)

        self._clear()
        self._set_status("Harvesting host: %s" % host)
        self._set_activity("building seed list...")
        self._log("\n[=] Harvest start for host: %s" % host)

        # Shared harvest state. Every worker touches these, so all reads/writes
        # of them go through `lock`. `work` is the thread-safe fetch queue;
        # `enqueued` dedups what we put on it (a URL is fetched at most once);
        # `seen` marks URLs already handled (incl. cached seeds we won't refetch).
        # RLock (reentrant) because _ingest_response runs under the lock and
        # calls enqueue(), which re-acquires it.
        lock = RLock()
        work = Queue()
        enqueued = set()
        seen = set()
        saved = {}
        manifest = []
        counters = {"fetched": 0}

        def enqueue(u):
            # Put a URL on the work queue once. Safe to call from any worker.
            with lock:
                if u in enqueued or u in seen:
                    return False
                enqueued.add(u)
                work.put(u)
                return True

        for m in msgs:
            try:
                u = h.analyzeRequest(m).getUrl().toString()
                resp = m.getResponse()
                if resp:
                    # Already have the response captured -> ingest it now and
                    # mark it handled so no worker refetches it. Any JS it
                    # references still gets enqueued for fetching.
                    with lock:
                        enqueued.add(u)
                        seen.add(u)
                        self._ingest_response(u, resp, saved, manifest, enqueue,
                                              host, scheme, from_cache=True)
                else:
                    enqueue(u)
            except Exception:
                pass

        seed_hosts = set([host]) | set(RELATED_HOSTS)

        sm_seeds = 0
        for sh in seed_hosts:
            try:
                for entry in self._cb.getSiteMap("%s://%s" % (scheme, sh)):
                    try:
                        url = h.analyzeRequest(entry).getUrl().toString()
                        if url.split("?")[0].lower().endswith((".js", ".mjs", ".map")):
                            if enqueue(url):
                                sm_seeds += 1
                    except Exception:
                        pass
            except Exception:
                pass

        # seed from Proxy history too (catches JS loaded but hidden by sitemap
        # scope/filters), for the primary host + any RELATED_HOSTS
        ph_seeds = 0
        try:
            for entry in self._cb.getProxyHistory():
                try:
                    if entry.getHttpService().getHost() not in seed_hosts:
                        continue
                    url = h.analyzeRequest(entry).getUrl().toString()
                    if url.split("?")[0].lower().endswith((".js", ".mjs", ".map")):
                        if enqueue(url):
                            ph_seeds += 1
                except Exception:
                    pass
        except Exception:
            pass

        enqueue(base_root)
        self._log("[=] %d seed URLs queued (sitemap:%d, proxy-history:+%d)"
                  % (len(enqueued), sm_seeds, ph_seeds))

        # ---- fetch everything with a small pool of workers ------------------
        # Parallelism caps at MAX_CONCURRENCY in-flight requests. Newly
        # discovered chunks are enqueued back onto `work` by _ingest_response,
        # so the BFS still reaches everything it did single-threaded.
        state = {"stopped": False}

        def worker():
            while True:
                try:
                    url = work.get(timeout=0.4)
                except Empty:
                    # Nothing queued right now. If we're stopping or the whole
                    # harvest is finished, exit; otherwise wait for more work.
                    if state["stopped"] or self._done.is_set():
                        return
                    continue
                try:
                    if state["stopped"]:
                        continue  # drain quietly; finally still marks task done
                    with lock:
                        if counters["fetched"] >= MAX_FILES:
                            skip = True
                        elif url in seen:
                            skip = True   # cached seed / already handled
                        else:
                            seen.add(url)
                            skip = False
                    if skip:
                        continue
                    self._set_activity("fetching: " + url)
                    try:
                        resp = self._fetch(url, tmpl, host)
                        if resp is None:
                            with lock:
                                manifest.append({"url": url, "ok": False,
                                                 "error": "no response / timeout"})
                        else:
                            with lock:
                                counters["fetched"] += 1
                                self._ingest_response(url, resp, saved, manifest,
                                                      enqueue, host, scheme)
                    except Exception as ex:
                        # isolate per-URL failures so one bad item never aborts
                        with lock:
                            manifest.append({"url": url, "ok": False,
                                             "error": str(ex)})
                        self._log("[-] processing failed: %s  (%s)" % (url, ex))
                    with lock:
                        self._set_progress(len(seen), work.qsize(), len(saved))
                    time.sleep(POLITE_DELAY)
                finally:
                    work.task_done()

        self._done = Event()
        workers = []
        for _ in range(MAX_CONCURRENCY):
            t = Thread(target=worker)
            t.setDaemon(True)
            t.start()
            workers.append(t)

        # Wait for the queue to drain (including everything discovered along
        # the way), while still honoring the Stop button and updating the bar.
        joiner = Thread(target=work.join)
        joiner.setDaemon(True)
        joiner.start()
        while joiner.isAlive():
            if self._stop:
                state["stopped"] = True
                break
            self._set_progress(len(seen), work.qsize(), len(saved))
            time.sleep(0.15)

        stopped = state["stopped"]
        # Signal workers to exit and let them unwind (they drain any remainder).
        self._done.set()
        for t in workers:
            t.join(1.0)

        self._set_activity(" ")
        self._log("[=] Fetched %d, saved %d JS asset(s).%s"
                  % (counters["fetched"], len(saved),
                     " (STOPPED)" if stopped else ""))
        self._set_status(("Stopped" if stopped else "Done") +
                         " - %d JS files from %s" % (len(saved), host))

        # host breakdown: shows exactly which origins served the assets
        # (so a CDN / CloudFront / S3 origin is obvious at a glance)
        host_counts = {}
        for m in manifest:
            if m.get("ok") and m.get("file"):
                try:
                    hh = urlparse(m["url"]).netloc
                except Exception:
                    hh = "?"
                host_counts[hh] = host_counts.get(hh, 0) + 1
        if host_counts:
            self._log("[=] Saved assets by host:")
            for hh, c in sorted(host_counts.items(), key=lambda kv: -kv[1]):
                tag = ""
                if hh != host:
                    tag = "  <- OFF-HOST (CDN/third-party)"
                self._log("      %5d  %s%s" % (c, hh, tag))

        manifest_blob = json.dumps(
            {"primary_host": host, "related_hosts": list(RELATED_HOSTS),
             "host_counts": host_counts, "items": manifest}, indent=2)
        self._export_zip(host, saved, manifest_blob)
        self._finish_progress(len(saved), stopped)

    # -- response handling ----------------------------------------------------
    def _ingest_response(self, url, resp_bytes, saved, manifest, enqueue,
                         host, scheme, from_cache=False):
        h = self._helpers
        try:
            info = h.analyzeResponse(resp_bytes)
            status = info.getStatusCode()
            body = h.bytesToString(resp_bytes)[info.getBodyOffset():]
            ctype = ""
            for hd in info.getHeaders():
                if hd.lower().startswith("content-type:"):
                    ctype = hd.split(":", 1)[1].strip().lower()
                    break
        except Exception as ex:
            manifest.append({"url": url, "ok": False, "error": "parse: %s" % ex})
            return

        if body is None:
            body = ""

        path_l = url.split("?")[0].lower()
        is_js = path_l.endswith((".js", ".mjs")) or "javascript" in ctype
        is_map = path_l.endswith(".map")
        is_asset = is_js or is_map

        if is_asset:
            fname = self._safe_name(url)
            n, final = 1, fname
            while final in saved and saved[final] != body:
                final = "%d__%s" % (n, fname)
                n += 1
            saved[final] = body
            manifest.append({"url": url, "ok": True, "file": final,
                             "status": status, "bytes": len(body),
                             "cached": from_cache})
            if not from_cache:
                self._log("[+] %4d  %s  (%d B)" % (len(saved), final, len(body)))
            # for every JS, also try its sibling sourcemap
            if is_js:
                base_js = url.split("?")[0]
                for cand in (base_js + ".map",):
                    enqueue(cand)
        else:
            manifest.append({"url": url, "ok": True, "status": status,
                             "ctype": ctype, "bytes": len(body), "saved": False})

        # discovery is isolated: a parse failure must not abort the harvest
        try:
            for u in self._discover(body, url):
                enqueue(u)
        except Exception as ex:
            self._log("[~] discover skipped for %s  (%s)" % (url, ex))

    # -- discovery ------------------------------------------------------------
    def _discover(self, text, base):
        out = set()
        if not text:
            return out
        for m in RE_SCRIPT_SRC.finditer(text):
            out.add(urljoin(base, m.group(1)))
        for m in RE_LINK.finditer(text):
            href = m.group(1) or m.group(2)
            if href and (".js" in href or ".mjs" in href):
                out.add(urljoin(base, href))
        for m in RE_JS_LITERAL.finditer(text):
            out.add(urljoin(base, m.group(1)))
        # explicit //# sourceMappingURL=... comments
        for m in RE_SOURCEMAP.finditer(text):
            sm = m.group(1).strip()
            if sm and not sm.startswith("data:"):
                out.add(urljoin(base, sm))
        out |= self._discover_webpack(text, base)
        return set(u for u in out if u.startswith("http"))

    def _discover_webpack(self, js, base):
        found = set()
        if not js:
            return found
        bases = []
        mp = RE_PUBLIC_PATH.search(js)
        if mp and mp.group(1):
            bases.append(urljoin(base, mp.group(1)))
        bases.append(base)

        assemblies = RE_PREFIX_SUFFIX.findall(js) or [("", ".js")]

        for mm in RE_MAP.finditer(js):
            kv = dict(RE_MAP_KV.findall(mm.group(1)))
            if len(kv) < 2:
                continue
            hashish = [v for v in kv.values() if re.match(r'^[0-9a-f]{5,}$', v)]
            if len(hashish) < max(1, len(kv) // 2):
                continue
            for cid, hsh in kv.items():
                cands = set()
                for pre, suf in assemblies:
                    cands.add("%s%s.%s%s" % (pre, cid, hsh, suf))
                    cands.add("%s%s%s" % (pre, hsh, suf))
                    cands.add("%s%s.%s.chunk.js" % (pre, cid, hsh))
                    cands.add("%s.%s.chunk.js" % (cid, hsh))
                    cands.add("%s.%s.js" % (cid, hsh))
                for b in bases:
                    for c in cands:
                        if c.endswith((".js", ".mjs")):
                            found.add(urljoin(b, c))
        return found

    # -- HTTP through Burp ----------------------------------------------------
    def _header_template(self, msg):
        h = self._helpers
        tmpl = {}
        try:
            for hd in h.analyzeRequest(msg).getHeaders():
                low = hd.lower()
                for key in ("cookie:", "user-agent:", "referer:", "authorization:"):
                    if low.startswith(key):
                        name, val = hd.split(":", 1)
                        tmpl[name.strip()] = val.strip()
        except Exception:
            pass
        return tmpl

    def _fetch(self, url, tmpl, seed_host):
        # Burp's makeHttpRequest is synchronous and can block forever when a
        # host is unreachable. Run it in a helper thread and abandon it after
        # FETCH_TIMEOUT so a single dead URL can't stall the whole harvest.
        result = {}

        def do():
            try:
                result["resp"] = self._do_fetch(url, tmpl, seed_host)
            except Exception as ex:
                result["err"] = ex

        t = Thread(target=do)
        t.setDaemon(True)
        t.start()
        t.join(FETCH_TIMEOUT)
        if t.isAlive():
            self._log("[-] timeout after %gs: %s" % (FETCH_TIMEOUT, url))
            return None     # orphaned helper thread unwinds on its own later
        if "err" in result:
            raise result["err"]
        return result.get("resp")

    def _do_fetch(self, url, tmpl, seed_host):
        h = self._helpers
        try:
            jurl = URL(url)
        except Exception:
            return None
        proto = jurl.getProtocol()
        host = jurl.getHost()
        port = jurl.getPort()
        if port == -1:
            port = 443 if proto == "https" else 80
        is_https = (proto == "https")

        req = h.buildHttpRequest(jurl)
        headers = list(h.analyzeRequest(req).getHeaders())
        drop = ("cookie:", "user-agent:", "referer:", "authorization:")
        headers = [hd for hd in headers if not hd.lower().startswith(drop)]

        apply = dict(tmpl)
        # Send session creds only to the primary host, or to RELATED_HOSTS when
        # explicitly opted in. Never to any other (third-party) host.
        cookie_ok = (host == seed_host) or \
            (SEND_COOKIES_TO_RELATED and host in RELATED_HOSTS)
        if not cookie_ok:
            apply.pop("Cookie", None)
            apply.pop("Authorization", None)
        for name, val in apply.items():
            headers.append("%s: %s" % (name, val))

        new_req = h.buildHttpMessage(headers, None)
        svc = h.buildHttpService(host, port, is_https)
        return self._cb.makeHttpRequest(svc, new_req).getResponse()

    # -- utilities ------------------------------------------------------------
    def _safe_name(self, url):
        p = urlparse(url)
        name = (p.path.strip("/").replace("/", "__")) or "index"
        if p.query:
            name += "__" + re.sub(r'[^\w.-]', "_", p.query)[:60]
        if not name.lower().endswith((".js", ".mjs", ".map")):
            name += ".js"
        return name

    def _export_zip(self, host, saved, manifest_blob):
        chooser = JFileChooser()
        chooser.setDialogTitle("Save JS harvest zip")
        default = "js_harvest_%s_%s.zip" % (
            re.sub(r'[^\w.-]', "_", host), time.strftime("%Y%m%d_%H%M%S"))
        chooser.setSelectedFile(File(default))
        if chooser.showSaveDialog(self._panel) != JFileChooser.APPROVE_OPTION:
            self._log("[!] Export cancelled; nothing written.")
            return
        out_path = chooser.getSelectedFile().getAbsolutePath()
        if not out_path.lower().endswith(".zip"):
            out_path += ".zip"
        try:
            zf = zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED)
            for fname, body in saved.items():
                zf.writestr("assets/" + fname, body.encode("utf-8"))
            zf.writestr("_manifest.json", manifest_blob.encode("utf-8"))
            zf.close()
            self._log("[=] DONE. %d files -> %s" % (len(saved) + 1, out_path))
        except Exception as ex:
            self._log("[!] Zip write failed: %s" % ex)
