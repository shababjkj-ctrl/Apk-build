"""
main.py — Kivy Android APK for SHAHIL Free Fire Network Monitor
Build with:  buildozer android debug
"""

import sys, os, threading, queue, time, json, re

# ── Android storage path ──
try:
    from android.storage import primary_external_storage_path
    STORAGE = os.path.join(primary_external_storage_path(), "SHAHIL")
except Exception:
    STORAGE = os.path.join(os.path.expanduser("~"), "SHAHIL")

os.makedirs(STORAGE, exist_ok=True)
os.chdir(STORAGE)          # all JSON files land here

# ── redirect stdout/stderr into our queue ──
_log_q: queue.Queue = queue.Queue(maxsize=30_000)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

class _Tee:
    def __init__(self, real):
        self._r = real
    def write(self, s):
        try: self._r.write(s)
        except Exception: pass
        clean = _ANSI.sub("", s)
        for ln in clean.splitlines():
            l = ln.rstrip()
            if l:
                try: _log_q.put_nowait(l)
                except queue.Full: pass
    def flush(self):
        try: self._r.flush()
        except Exception: pass
    def __getattr__(self, a): return getattr(self._r, a)

sys.stdout = _Tee(sys.stdout)
sys.stderr = _Tee(sys.stderr)

# ── import capture engine ──
import importlib.util as _ilu
_me = os.path.dirname(os.path.abspath(__file__))
_spec = _ilu.spec_from_file_location("udpcapture", os.path.join(_me, "udpcapture_1.py"))
_cap = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_cap)

# ── Kivy ──
from kivy.config import Config
Config.set("graphics", "width",  "400")
Config.set("graphics", "height", "800")

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.widget import Widget
from kivy.graphics import Color, Rectangle

Window.clearcolor = (0.04, 0.05, 0.06, 1)

# ── colors ──
C_BG     = (0.04,  0.05,  0.06,  1)
C_PANEL  = (0.08,  0.10,  0.13,  1)
C_BORDER = (0.13,  0.15,  0.18,  1)
C_TEXT   = (0.90,  0.93,  0.95,  1)
C_DIM    = (0.54,  0.58,  0.62,  1)
C_ACCENT = (0.00,  0.898, 1.00,  1)
C_GREEN  = (0.247, 0.714, 0.314, 1)
C_RED    = (0.973, 0.318, 0.286, 1)
C_YELLOW = (0.827, 0.60,  0.133, 1)
C_BLUE   = (0.345, 0.651, 1.00,  1)


def mk_btn(text, bg, fg=(1,1,1,1), **kw):
    b = Button(text=text, background_normal="", background_color=bg,
               color=fg, bold=True, **kw)
    return b


def mk_label(text="", color=None, size_hint_x=1, **kw):
    return Label(text=text, color=color or C_TEXT,
                 size_hint_x=size_hint_x,
                 text_size=(None, None),
                 halign="left", valign="middle",
                 font_name="RobotoMono-Regular" if os.path.exists(
                     "/system/fonts/RobotoMono-Regular.ttf") else "Roboto",
                 **kw)


# ── capture thread control ──
_running = threading.Event()
_cap_thread = None


def _run_capture():
    try:
        _cap.load_existing()
        _cap.ensure_udp_relay()
        t1 = threading.Thread(target=_cap.run_http, daemon=True)
        t2 = threading.Thread(target=_cap.run_tcp,  daemon=True)
        t1.start(); t2.start()
        _running.set()
        while _running.is_set():
            time.sleep(0.5)
    except Exception as e:
        print(f"[capture] error: {e}")
    finally:
        _cap.save_all(force=True)
        _running.clear()


def start_capture():
    global _cap_thread
    if _running.is_set():
        return
    _cap_thread = threading.Thread(target=_run_capture, daemon=True)
    _cap_thread.start()


def stop_capture():
    _running.clear()
    _cap.save_all(force=True)


# ── Android share / open file ──
def _share_file(path):
    try:
        from android import activity
        from jnius import autoclass
        Intent   = autoclass("android.content.Intent")
        Uri      = autoclass("android.net.Uri")
        File     = autoclass("java.io.File")
        FileProvider = autoclass("androidx.core.content.FileProvider")

        f    = File(path)
        ctx  = activity._activity
        uri  = FileProvider.getUriForFile(
                   ctx,
                   ctx.getPackageName() + ".fileprovider",
                   f)
        intent = Intent(Intent.ACTION_SEND)
        intent.setType("application/json")
        intent.putExtra(Intent.EXTRA_STREAM, uri)
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        activity.startActivity(Intent.createChooser(intent, "Share file"))
    except Exception as e:
        print(f"[share] {e}")
        # fallback: copy to Downloads
        try:
            import shutil
            dl = "/sdcard/Download"
            os.makedirs(dl, exist_ok=True)
            shutil.copy2(path, os.path.join(dl, os.path.basename(path)))
            print(f"[share] saved to Download/{os.path.basename(path)}")
        except Exception as e2:
            print(f"[share fallback] {e2}")


# ═══════════════════════════════════════════════════════
#  MAIN UI
# ═══════════════════════════════════════════════════════

class LogScreen(BoxLayout):
    def __init__(self, **kw):
        super().__init__(orientation="vertical", spacing=0, **kw)
        self._lines   = []        # all log strings
        self._filter  = ""
        self._auto_scroll = True
        self._last_count  = 0

        self._build_header()
        self._build_toolbar()
        self._build_log()
        self._build_downloads()
        self._build_statusbar()

        Clock.schedule_interval(self._tick, 0.25)

    # ── header ────────────────────────────────────────
    def _build_header(self):
        hdr = BoxLayout(size_hint_y=None, height=52,
                        padding=[12, 8, 12, 8], spacing=10)
        with hdr.canvas.before:
            Color(*C_PANEL)
            self._hdr_rect = Rectangle(pos=hdr.pos, size=hdr.size)
        hdr.bind(pos=self._upd_hdr, size=self._upd_hdr)

        self._dot = Label(text="●", color=C_RED, font_size=14,
                          size_hint=(None, 1), width=18)
        hdr.add_widget(self._dot)

        title = Label(text="[b]SHAHIL[/b]  [color=8b949e]FF Monitor[/color]",
                      markup=True, color=C_ACCENT, font_size=16,
                      halign="left", valign="middle")
        hdr.add_widget(title)

        self._btn_toggle = mk_btn("▶  Start", bg=(0.05, 0.17, 0.11, 1),
                                  color=(*C_GREEN[:3], 1),
                                  size_hint=(None, 1), width=100)
        self._btn_toggle.bind(on_release=self._on_toggle)
        hdr.add_widget(self._btn_toggle)

        clr = mk_btn("🗑", bg=C_PANEL, size_hint=(None, 1), width=44, font_size=16)
        clr.bind(on_release=self._on_clear)
        hdr.add_widget(clr)

        self.add_widget(hdr)

    def _upd_hdr(self, inst, val):
        self._hdr_rect.pos  = inst.pos
        self._hdr_rect.size = inst.size

    # ── filter toolbar ─────────────────────────────────
    def _build_toolbar(self):
        bar = BoxLayout(size_hint_y=None, height=40,
                        padding=[10, 4, 10, 4], spacing=8)
        with bar.canvas.before:
            Color(0.08, 0.10, 0.13, 1)
            self._bar_rect = Rectangle(pos=bar.pos, size=bar.size)
        bar.bind(pos=lambda i,v: setattr(self._bar_rect,'pos',v),
                 size=lambda i,v: setattr(self._bar_rect,'size',v))

        self._filt = TextInput(hint_text="filter… (regex ok)",
                               multiline=False,
                               background_color=(0.10, 0.12, 0.16, 1),
                               foreground_color=C_TEXT,
                               cursor_color=C_ACCENT,
                               font_size=12,
                               size_hint=(1, 1))
        self._filt.bind(text=self._on_filter)
        bar.add_widget(self._filt)

        self._ascroll_btn = mk_btn("⇩", bg=(0.08, 0.20, 0.08, 1),
                                   color=(*C_GREEN[:3],1),
                                   size_hint=(None,1), width=38, font_size=16)
        self._ascroll_btn.bind(on_release=self._toggle_scroll)
        bar.add_widget(self._ascroll_btn)

        self.add_widget(bar)

    # ── log scroll area ────────────────────────────────
    def _build_log(self):
        self._sv = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self._log_grid = GridLayout(cols=1, size_hint_y=None, spacing=1,
                                    padding=[8, 4, 8, 4])
        self._log_grid.bind(minimum_height=self._log_grid.setter("height"))
        self._sv.add_widget(self._log_grid)
        self.add_widget(self._sv)

    # ── downloads panel ────────────────────────────────
    def _build_downloads(self):
        dl = GridLayout(cols=3, size_hint_y=None, height=96,
                        padding=[8, 6, 8, 6], spacing=4)
        with dl.canvas.before:
            Color(*C_PANEL)
            self._dl_rect = Rectangle(pos=dl.pos, size=dl.size)
        dl.bind(pos=lambda i,v: setattr(self._dl_rect,'pos',v),
                size=lambda i,v: setattr(self._dl_rect,'size',v))

        files = [
            ("HTTP",         "Https.json"),
            ("TCP",          "Tcp_PaCket.json"),
            ("UDP raw",      "Udp_PaCkets.json"),
            ("UDP decoded",  "Udp_DeCoded_DaTa.json"),
            ("UDP keys",     "UdpxKey.json"),
            ("Session keys", "session_keys.json"),
        ]
        for label, fname in files:
            b = mk_btn(f"↓ {label}", bg=(0.10, 0.13, 0.18, 1),
                       color=(*C_ACCENT[:3],1), font_size=10)
            b._fname = fname
            b.bind(on_release=self._on_download)
            dl.add_widget(b)

        self.add_widget(dl)

    # ── status bar ─────────────────────────────────────
    def _build_statusbar(self):
        sb = BoxLayout(size_hint_y=None, height=28,
                       padding=[10, 2, 10, 2], spacing=10)
        with sb.canvas.before:
            Color(0.06, 0.07, 0.09, 1)
            self._sb_rect = Rectangle(pos=sb.pos, size=sb.size)
        sb.bind(pos=lambda i,v: setattr(self._sb_rect,'pos',v),
                size=lambda i,v: setattr(self._sb_rect,'size',v))

        self._stat_lbl = Label(
            text="HTTP:0  TCP:0  UDP:0  Decoded:0  Keys:0",
            color=C_DIM, font_size=10, halign="left", valign="middle")
        sb.add_widget(self._stat_lbl)
        self.add_widget(sb)

    # ── classify ───────────────────────────────────────
    @staticmethod
    def _classify(txt):
        if re.search(r"C2S|→ server|client →", txt, re.I): return "c2s"
        if re.search(r"S2C|← server|server →", txt, re.I): return "s2c"
        if re.search(r"KEY|LOADED|🔑",          txt, re.I): return "key"
        if re.search(r"error|failed|ERR|✗|❌",  txt, re.I): return "err"
        if re.search(r"✅|started|listening",    txt, re.I): return "ok"
        return "dim"

    _COLORS = {"c2s": (0.95, 0.65, 0.00, 1),
               "s2c": (*C_BLUE[:3], 1),
               "key": (*C_GREEN[:3], 1),
               "err": (*C_RED[:3], 1),
               "ok":  (*C_ACCENT[:3], 1),
               "dim": C_DIM}

    def _add_line(self, raw):
        self._lines.append(raw)
        if len(self._lines) > 20_000:
            self._lines = self._lines[-15_000:]

        if self._filter and not re.search(self._filter, raw, re.I):
            return

        cls   = self._classify(raw)
        color = self._COLORS.get(cls, C_DIM)
        lbl   = Label(text=raw,
                      color=color,
                      font_size=11,
                      size_hint_y=None,
                      text_size=(Window.width - 20, None),
                      halign="left", valign="top")
        lbl.bind(texture_size=lbl.setter("size"))
        self._log_grid.add_widget(lbl)

        # cap visible lines
        kids = self._log_grid.children
        if len(kids) > 3000:
            to_rm = kids[-500:]
            for w in to_rm:
                self._log_grid.remove_widget(w)

    def _rebuild_log(self):
        self._log_grid.clear_widgets()
        filt = self._filter
        for raw in self._lines:
            if filt and not re.search(filt, raw, re.I):
                continue
            cls   = self._classify(raw)
            color = self._COLORS.get(cls, C_DIM)
            lbl   = Label(text=raw, color=color, font_size=11,
                          size_hint_y=None,
                          text_size=(Window.width - 20, None),
                          halign="left", valign="top")
            lbl.bind(texture_size=lbl.setter("size"))
            self._log_grid.add_widget(lbl)

    # ── clock tick ─────────────────────────────────────
    def _tick(self, dt):
        # drain log queue
        batch = []
        try:
            while True:
                batch.append(_log_q.get_nowait())
        except queue.Empty:
            pass
        for ln in batch:
            self._add_line(ln)

        # auto-scroll
        if self._auto_scroll and batch:
            self._sv.scroll_y = 0

        # status dot
        running = _running.is_set()
        self._dot.color = (*C_GREEN[:3], 1) if running else (*C_RED[:3], 1)
        if running:
            self._btn_toggle.text = "■  Stop"
            self._btn_toggle.background_color = (0.17, 0.05, 0.05, 1)
            self._btn_toggle.color = (*C_RED[:3], 1)
        else:
            self._btn_toggle.text = "▶  Start"
            self._btn_toggle.background_color = (0.05, 0.17, 0.11, 1)
            self._btn_toggle.color = (*C_GREEN[:3], 1)

        # stats
        self._stat_lbl.text = (
            f"HTTP:{len(_cap.http_capture)}  "
            f"TCP:{len(_cap.tcp_capture)}  "
            f"UDP:{_cap.UDP_PACKETS_RECEIVED}  "
            f"Dec:{len(_cap.udp_decoded)}  "
            f"Keys:{len(_cap.session_keys_history)}"
        )

    # ── events ─────────────────────────────────────────
    def _on_toggle(self, btn):
        if _running.is_set():
            stop_capture()
            self._add_line("» Capture stopped.")
        else:
            self._add_line(f"» Starting capture — files → {STORAGE}")
            start_capture()

    def _on_clear(self, btn):
        with _cap.http_lock:  _cap.http_capture.clear()
        with _cap.tcp_lock:   _cap.tcp_capture.clear()
        with _cap.udp_lock:   _cap.udp_capture.clear()
        with _cap.udp_decoded_lock: _cap.udp_decoded.clear()
        with _cap.udp_keys_lock:    _cap.udp_keys_history.clear()
        with _cap.keys_lock:        _cap.session_keys_history.clear()
        _cap.UDP_PACKETS_RECEIVED = 0
        while not _log_q.empty():
            try: _log_q.get_nowait()
            except queue.Empty: break
        self._lines.clear()
        self._log_grid.clear_widgets()
        self._add_line("» Cleared.")

    def _on_filter(self, inst, val):
        self._filter = val.strip()
        self._rebuild_log()

    def _toggle_scroll(self, btn):
        self._auto_scroll = not self._auto_scroll
        btn.background_color = (0.08, 0.20, 0.08, 1) if self._auto_scroll else (0.20, 0.08, 0.08, 1)

    def _on_download(self, btn):
        fname = btn._fname
        path  = os.path.join(STORAGE, fname)
        if not os.path.exists(path):
            self._add_line(f"» {fname} not found yet.")
            return
        self._add_line(f"» Sharing {fname} …")
        threading.Thread(target=_share_file, args=(path,), daemon=True).start()


class ShahilApp(App):
    def build(self):
        self.title = "SHAHIL — FF Monitor"
        return LogScreen()


if __name__ == "__main__":
    ShahilApp().run()
