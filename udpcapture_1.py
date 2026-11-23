import sys, os, json, time, atexit, signal, ssl, socket, threading, asyncio, re
import struct, itertools
import gzip, zlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import urllib.request, urllib.error

try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn
    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

# Internal DNS resolver fallback for Garena servers (fixes [Errno 11001] getaddrinfo failed on ISP DNS)
_GARENA_DNS_MAP = {
    'loginbp.ppmainecoonghj.com': '202.81.97.46',
    'loginbp.ggpolarbear.com': '202.81.97.46',
    'login.ind.freefiremobile.com': '202.81.96.6',
    'client.ind.freefiremobile.com': '148.222.69.68',
    'clientbp.ppmainecoonghj.com': '148.222.66.29',
    'clientbp.ggpolarbear.com': '148.222.66.29',
    'version.ggwhitehawk.com': '202.81.119.5',
    'ffmconnect.ppmainecoonghj.com': '34.126.190.150',
    '100067.connect.garena.com': '49.44.79.236',
    'bdevent.ggpolarbear.com': '202.81.106.83',
    'dl-bs.ggpolarbear.com': '103.137.168.56',
    'dl.dir.freefiremobile.com': '121.244.205.240',
    'dl.cdn.freefiremobile.com': '34.104.32.54',
    'ffmconnect.live.gop.garenanow.com': '34.124.158.229',
}

_orig_getaddrinfo = socket.getaddrinfo

def _fallback_getaddrinfo(host, port, *args, **kwargs):
    try:
        return _orig_getaddrinfo(host, port, *args, **kwargs)
    except Exception:
        if host in _GARENA_DNS_MAP:
            return _orig_getaddrinfo(_GARENA_DNS_MAP[host], port, *args, **kwargs)
        raise

socket.getaddrinfo = _fallback_getaddrinfo

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R, G, Y, B, M, C, W = (Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE,
                            Fore.MAGENTA, Fore.CYAN, Fore.WHITE)
    BOLD, DIM, RESET = Style.BRIGHT, Style.DIM, Style.RESET_ALL
except ImportError:
    R = G = Y = B = M = C = W = BOLD = DIM = RESET = ""


AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

HTTP_PORT       = 3030
TCP_ONLINE_PORT = 7090
TCP_CHAT_PORT   = 7080
UDP_MATCH_PORT  = 5080

LOCAL_MATCH_ADDR = f"127.0.0.1:{UDP_MATCH_PORT}"

HTTP_CAPTURE_FILE  = "Https.json"
TCP_CAPTURE_FILE   = "Tcp_PaCket.json"
UDP_CAPTURE_FILE   = "Udp_PaCkets.json"
UDP_DECODED_FILE   = "Udp_DeCoded_DaTa.json"
UDP_KEYS_FILE      = "UdpxKey.json"
KEYS_FILE          = "session_keys.json"
LOCALCONFIG_FILE   = "localconfig.json"

SAVE_INTERVAL = 0.5
MODIFIED_FIELD_20_VALUE = "27.59.76.116"

REAL_LOGIN_HOST  = "loginbp.ppmainecoonghj.com"
REAL_CLIENT_HOST = "clientbp.ppmainecoonghj.com"

ROUTE_BY_PATH = {
    "/ver.php": "version.ggwhitehawk.com",
    "/MajorLogin": REAL_LOGIN_HOST,
    "/MajorRegister": REAL_LOGIN_HOST,
    "/GenerateNickname": REAL_LOGIN_HOST,
    "/ChooseNewbieChoice": REAL_LOGIN_HOST,
    "/GetLoginData": REAL_CLIENT_HOST,
    "/GetWallet": REAL_CLIENT_HOST,
    "/CreateClan": REAL_CLIENT_HOST,
    "/Ping": REAL_CLIENT_HOST,
    "/GetPlayerPersonalInfo": REAL_CLIENT_HOST,
    "/GetPlayerDailyRankingSummary": REAL_CLIENT_HOST,
    "/GetPlayerProfile": REAL_CLIENT_HOST,
    "/GetPlayerStats": REAL_CLIENT_HOST,
    "/GetRankInfo": REAL_CLIENT_HOST,
    "/GetPlayerGalleryInfo": REAL_CLIENT_HOST,
    "/GetPlayerBasicInfo": REAL_CLIENT_HOST,
    "/GetFriend": REAL_CLIENT_HOST,
    "/GetFriendList": REAL_CLIENT_HOST,
    "/GetRecent": REAL_CLIENT_HOST,
    "/GetRankingList": REAL_CLIENT_HOST,
    "/GetLeaderboard": REAL_CLIENT_HOST,
    "/GetAnnouncement": REAL_CLIENT_HOST,
    "/GetConfig": REAL_CLIENT_HOST,
    "/GetRegionConfig": REAL_CLIENT_HOST,
    "/GetStore": REAL_CLIENT_HOST,
    "/GetStoreItems": REAL_CLIENT_HOST,
    "/GetInventory": REAL_CLIENT_HOST,
    "/GetPets": REAL_CLIENT_HOST,
    "/GetLoadout": REAL_CLIENT_HOST,
    "/GetLoadoutList": REAL_CLIENT_HOST,
    "/GetAchievement": REAL_CLIENT_HOST,
    "/GetQuest": REAL_CLIENT_HOST,
    "/GetMission": REAL_CLIENT_HOST,
    "/GetEvent": REAL_CLIENT_HOST,
    "/GetEvents": REAL_CLIENT_HOST,
    "/GetMail": REAL_CLIENT_HOST,
    "/GetMailList": REAL_CLIENT_HOST,
    "/GetTeam": REAL_CLIENT_HOST,
    "/GetTeamInfo": REAL_CLIENT_HOST,
    "/GetLobby": REAL_CLIENT_HOST,
    "/GetLobbyInfo": REAL_CLIENT_HOST,
    "/GetAccountWeaponPowerTitleRecord": REAL_CLIENT_HOST,
    "/GetGiftStoreDetails": REAL_CLIENT_HOST,
    "/GetItemsWishCnts": REAL_CLIENT_HOST,
    "/GetPlayerPeriodicRankingInfoByAccountID": REAL_CLIENT_HOST,
    "/GetPlayerPersonalShow": REAL_CLIENT_HOST,
    "/GetPlayerTCStats": REAL_CLIENT_HOST,
    "/GetWishListItems": REAL_CLIENT_HOST,
    "/QueryOccupationDetail": REAL_CLIENT_HOST,

}
DEFAULT_HOST  = REAL_CLIENT_HOST
ALLOWED_HOSTS = {REAL_LOGIN_HOST, REAL_CLIENT_HOST}

AES_OFFSETS        = [0, 1, 2, 3, 4, 5, 6, 8, 12, 16]
SKIP_PACKET_TYPES  = {"0214", "0215"}
MAJOR_LOGIN_OFFSET = 64
MATCH_FRAME_TYPES  = ("0300", "0e00")

_PROXY_URL = f"http://127.0.0.1:{HTTP_PORT}/"

CONFIG_JSON = json.dumps({
    "serverLoginUrl":      _PROXY_URL,
    "serverUrl":           _PROXY_URL,
    "loginServerUrl":      _PROXY_URL,
    "contentServerUrl":    _PROXY_URL,
    "serverUrlDebug":      _PROXY_URL,
    "url":                 _PROXY_URL,
    "login_url":           _PROXY_URL,
    "server_url":          _PROXY_URL,
    "server_login_url":    _PROXY_URL,
    "content_server_url":  _PROXY_URL,
    "resetGuest":          False,  # Fixed: Do not wipe guest accounts
}, indent=2)

GAME_PATHS = {
    "normal": "/storage/emulated/0/Android/data/com.dts.freefireth/files/localconfig.json",
    "max":    "/storage/emulated/0/Android/data/com.dts.freefiremax/files/localconfig.json",
}



CRC7_TABLE = bytes([
    0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,25,16,11,2,61,52,47,38,
    81,88,67,74,117,124,103,110,50,59,32,41,22,31,4,13,122,115,104,97,94,87,76,69,
    43,34,57,48,15,6,29,20,99,106,113,120,71,78,85,92,100,109,118,127,64,73,82,91,
    44,37,62,55,8,1,26,19,125,116,111,102,89,80,75,66,53,60,39,46,17,24,3,10,
    86,95,68,77,114,123,96,105,30,23,12,5,58,51,40,33,79,70,93,84,107,98,121,112,
    7,14,21,28,35,42,49,56,65,72,83,90,101,108,119,126,9,0,27,18,45,36,63,54,
    88,81,74,67,124,117,110,103,16,25,2,11,52,61,38,47,115,122,97,104,87,94,69,76,
    59,50,41,32,31,22,13,4,106,99,120,113,78,71,92,85,34,43,48,57,6,15,20,29,
    37,44,55,62,1,8,19,26,109,100,127,118,73,64,91,82,60,53,46,39,24,17,10,3,
    116,125,102,111,80,89,66,75,23,30,5,12,51,58,33,40,95,86,77,68,123,114,105,96,
    14,7,28,21,42,35,56,49,70,79,84,93,98,107,112,121,
])

TEA_M      = 0xFFFFFFFF
TEA_DELTA  = 0x9E3779B9
TEA_ROUNDS = 16

UDP_FIELD_SIZES = {0: 1, 1: 2, 2: 2, 3: 1, 4: 2}
UDP_FIELD_NAMES = {0: "sendOption", 1: "cmd", 2: "orderId", 3: "flags", 4: "length"}

UDP_CMD_NAMES = {
    1:   "HELLO",
    2:   "ACK",
    3:   "PING",
    101: "SERVER_STATE",
    447: "MATCH_PROCESS",
    448: "MATCH_LOADING",
    849: "BULK_STATE",
}

_IPPORT_RE        = re.compile(rb"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$")
_IPPORT_SEARCH_RE = re.compile(rb"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}")
_HEX16_RE         = re.compile(r"^[0-9a-fA-F]{32}$")
_MASK_RE          = re.compile(r"^[0-4]{5}$")



http_capture = []
tcp_capture  = []
udp_capture  = []
udp_decoded  = []
udp_keys_history = []
session_keys_history = []

http_lock = threading.Lock()
tcp_lock  = threading.Lock()
udp_lock  = threading.Lock()
udp_decoded_lock = threading.Lock()
udp_keys_lock    = threading.Lock()
keys_lock = threading.Lock()

_last_save = {"http": 0.0, "tcp": 0.0, "udp": 0.0, "keys": 0.0,
              "udp_decoded": 0.0, "udp_keys": 0.0}

ONLINE_TARGET = None
CHAT_TARGET   = None
MATCH_TARGET  = None
state_lock    = threading.Lock()

SESSION_KEY   = None
SESSION_IV    = None
SESSION_READY = False
session_lock  = threading.Lock()

UDP_ACTIVE_KEY        = None
UDP_ACTIVE_LAYOUT_STR = None
UDP_ACTIVE_TYPE       = None
udp_key_lock          = threading.Lock()

UDP_RELAY_SOCK = None
udp_sock_lock  = threading.Lock()
UDP_PACKETS_RECEIVED = 0

HTTP_SERVER_REF = None

counters = {"online_c2s": 0, "online_s2c": 0,
            "chat_c2s":   0, "chat_s2c":   0,
            "udp_c2s":    0, "udp_s2c":    0,
            "http_req":   0}


def _throttled(chan, force):
    now = time.time()
    if not force and (now - _last_save[chan]) < SAVE_INTERVAL: return False
    _last_save[chan] = now
    return True


def _atomic_write(path, lock, data, tag):
    with lock:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f: json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            print(f"{R}[save_{tag}] {e}{RESET}")


def save_http(force=False):
    if not _throttled("http", force): return
    _atomic_write(HTTP_CAPTURE_FILE, http_lock, http_capture, "http")

def save_tcp(force=False):
    if not _throttled("tcp", force): return
    _atomic_write(TCP_CAPTURE_FILE, tcp_lock, tcp_capture, "tcp")

def save_udp(force=False):
    if not _throttled("udp", force): return
    _atomic_write(UDP_CAPTURE_FILE, udp_lock, udp_capture, "udp")

def save_udp_decoded(force=False):
    if not _throttled("udp_decoded", force): return
    _atomic_write(UDP_DECODED_FILE, udp_decoded_lock, udp_decoded, "udp_decoded")

def save_udp_keys(force=True):
    if not _throttled("udp_keys", force): return
    _atomic_write(UDP_KEYS_FILE, udp_keys_lock, udp_keys_history, "udp_keys")

def save_keys(force=True):
    if not _throttled("keys", force): return
    _atomic_write(KEYS_FILE, keys_lock, session_keys_history, "keys")

def save_all(force=True):
    save_http(force); save_tcp(force); save_udp(force)
    save_keys(force); save_udp_decoded(force); save_udp_keys(force)


def load_existing():
    print(f"\n{BOLD}{Y}Loading existing capture files (append mode)...{RESET}")
    for path, lock, target, name in (
        (HTTP_CAPTURE_FILE, http_lock, http_capture, "http"),
        (TCP_CAPTURE_FILE,  tcp_lock,  tcp_capture,  "tcp"),
        (UDP_CAPTURE_FILE,  udp_lock,  udp_capture,  "udp"),
        (UDP_DECODED_FILE,  udp_decoded_lock, udp_decoded, "udp_decoded"),
        (UDP_KEYS_FILE,     udp_keys_lock, udp_keys_history, "udp_keys"),
        (KEYS_FILE,         keys_lock, session_keys_history, "keys"),
    ):
        loaded = 0
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    loaded = len(data)
                    target.extend(data)
            except Exception as e:
                print(f"{Y}  ⚠ {name}: {e}{RESET}")
        print(f"{G}  ✅ {name}: {loaded} entries preserved{RESET}" if loaded
              else f"{DIM}  · {name}: empty{RESET}")
        if not os.path.exists(path):
            _atomic_write(path, lock, target, name)


def install_localconfig():
    print(f"\n{BOLD}{M}╔══════════════════════════════════════════════════════════════════╗")
    print("║  AUTO-INSTALL — writing localconfig.json to game folders         ║")
    print("╚══════════════════════════════════════════════════════════════════╝{RESET}")
    installed = []
    for label, path in GAME_PATHS.items():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f: f.write(CONFIG_JSON)
            print(f"{G}  ✅ [{label}] {path}{RESET}")
            installed.append(path)
        except Exception as e:
            print(f"{Y}  ⚠ [{label}] {path} — {e}{RESET}")
    if not installed:
        print(f"{R}  ⚠ Could not install to any game folder.{RESET}")
    return installed


def remove_localconfig(installed):
    print(f"\n{BOLD}{M}╔══════════════════════════════════════════════════════════════════╗")
    print("║  AUTO-REMOVE — cleaning up localconfig.json                     ║")
    print("╚══════════════════════════════════════════════════════════════════╝{RESET}")
    for path in installed:
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"{G}  ✅ removed {path}{RESET}")
        except Exception as e:
            print(f"{Y}  ⚠ {path} — {e}{RESET}")


# ============================================================
# AES + PROTOBUF CORE
# ============================================================
def aes_decrypt(data, key=AES_KEY, iv=AES_IV):
    try:
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), AES.block_size)
    except Exception:
        try:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
        except Exception:
            return None


def aes_encrypt(data, key=AES_KEY, iv=AES_IV):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))


def _try_aes_at(data, key, iv, offset):
    if offset >= len(data): return None
    payload = data[offset:]
    if len(payload) < 16 or len(payload) % 16 != 0: return None
    try:
        pt = aes_decrypt(payload, key, iv)
        if pt and _looks_like_proto(pt): return pt
    except Exception: return None
    return None


def _read_varint(d, o):
    r = 0; s = 0
    while True:
        if o >= len(d): raise ValueError("end")
        b = d[o]; o += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
        if s > 63: raise ValueError("long")
    return r, o


def _encode_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); break
    return bytes(out)


def parse_proto_flat(data):
    out = {}; off = 0
    while off < len(data):
        try: tag, off = _read_varint(data, off)
        except Exception: break
        field = tag >> 3; wire = tag & 0x07
        if field == 0: break
        try:
            if wire == 0: val, off = _read_varint(data, off)
            elif wire == 1: val = data[off:off+8]; off += 8
            elif wire == 2:
                ln, off = _read_varint(data, off)
                val = data[off:off+ln]; off += ln
            elif wire == 5: val = data[off:off+4]; off += 4
            else: break
        except Exception: break
        if field in out:
            if isinstance(out[field], list): out[field].append(val)
            else: out[field] = [out[field], val]
        else: out[field] = val
    return out


def _parse_ordered(data):
    out, off = [], 0
    while off < len(data):
        try: tag, off = _read_varint(data, off)
        except Exception: break
        field = tag >> 3; wire = tag & 0x07
        if field == 0: break
        try:
            if wire == 0:
                v, off = _read_varint(data, off)
                out.append((field, 0, _encode_varint(v), v))
            elif wire == 1:
                c = data[off:off+8]; off += 8
                out.append((field, 1, c, int.from_bytes(c, "little")))
            elif wire == 2:
                ln, off = _read_varint(data, off)
                c = data[off:off+ln]; off += ln
                out.append((field, 2, c, c))
            elif wire == 5:
                c = data[off:off+4]; off += 4
                out.append((field, 5, c, int.from_bytes(c, "little")))
            else: break
        except Exception: break
    return out


def _rebuild(fields):
    out = bytearray()
    for f, w, raw, _ in fields:
        out += _encode_varint((f << 3) | w)
        if w in (0, 1, 5): out += raw
        elif w == 2: out += _encode_varint(len(raw)) + raw
    return bytes(out)


def _rewrite_ip_port_deep(buf, new_bytes):
    fields = _parse_ordered(buf)
    if not fields: return None, None
    for i, (f, w, r, v) in enumerate(fields):
        if w != 2 or not isinstance(r, bytes) or not r: continue
        if _IPPORT_RE.match(r):
            fields[i] = (f, 2, new_bytes, new_bytes)
            return _rebuild(fields), r
        if len(r) >= 4:
            inner, old = _rewrite_ip_port_deep(r, new_bytes)
            if inner is not None:
                fields[i] = (f, 2, inner, inner)
                return _rebuild(fields), old
    return None, None


def _looks_like_proto(data):
    if not data or len(data) < 2: return False
    try: tag, _ = _read_varint(data, 0)
    except Exception: return False
    f = tag >> 3; w = tag & 7
    return 1 <= f <= 536870911 and w in (0, 1, 2, 5)


def replace_fields_in_proto(data, replacements):
    out = bytearray(); off = 0
    while off < len(data):
        start = off
        try: tag, off = _read_varint(data, off)
        except Exception: out.extend(data[start:]); break
        field = tag >> 3; wire = tag & 0x07
        try:
            if wire == 0: _, off = _read_varint(data, off)
            elif wire == 1: off += 8
            elif wire == 2:
                ln, off = _read_varint(data, off); off += ln
            elif wire == 5: off += 4
            else: out.extend(data[start:]); break
        except Exception: out.extend(data[start:]); break
        if field in replacements and wire == 2:
            nv = replacements[field]
            if isinstance(nv, str): nv = nv.encode("utf-8")
            out += _encode_varint((field << 3) | 2)
            out += _encode_varint(len(nv)) + nv
        else: out.extend(data[start:off])
    return bytes(out)


def decode_protobuf_recursive(data, depth=0, max_depth=10):
    if depth > max_depth: return []
    fields = []; off = 0
    while off < len(data):
        start = off
        try: tag, off = _read_varint(data, off)
        except Exception: break
        field = tag >> 3; wire = tag & 7
        if field == 0 or field > 536870911: break
        try:
            if wire == 0:
                v, off = _read_varint(data, off)
                fields.append((field, "VARINT", v, None))
            elif wire == 1:
                if off+8 > len(data): break
                raw = data[off:off+8]; off += 8
                fields.append((field, "FIXED64", int.from_bytes(raw, "little"), None))
            elif wire == 5:
                if off+4 > len(data): break
                raw = data[off:off+4]; off += 4
                fields.append((field, "FIXED32", int.from_bytes(raw, "little"), None))
            elif wire == 2:
                ln, off = _read_varint(data, off)
                if off+ln > len(data): break
                payload = data[off:off+ln]; off += ln
                text = None
                try:
                    s = payload.decode("utf-8")
                    if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s): text = s
                except Exception: pass
                if text is not None:
                    fields.append((field, "STRING", text, None)); continue
                nested = None
                if len(payload) >= 2 and _looks_like_proto(payload):
                    try: nested = decode_protobuf_recursive(payload, depth+1, max_depth)
                    except Exception: nested = None
                if nested: fields.append((field, "MESSAGE", len(payload), nested))
                else: fields.append((field, "BYTES", payload.hex(), None))
            else: break
        except Exception: break
        if off <= start: break
    return fields


def format_protobuf_tree(fields, indent="      "):
    lines = []
    for num, wt, val, nested in fields:
        if wt == "MESSAGE":
            lines.append(f"{indent}field {num:<3} MESSAGE   ({val} bytes)")
            if nested: lines.extend(format_protobuf_tree(nested, indent + "  "))
        elif wt == "BYTES":
            v = val if len(val) <= 64 else val[:64] + "…"
            lines.append(f"{indent}field {num:<3} BYTES     0x{v}")
        elif wt == "STRING":
            v = val if len(val) <= 100 else val[:100] + "…"
            lines.append(f"{indent}field {num:<3} STRING    \"{v}\"")
        else: lines.append(f"{indent}field {num:<3} {wt:<9} {val}")
    return lines


def hex_lines(data, per_line=32):
    return [data[i:i+per_line].hex().upper() for i in range(0, len(data), per_line)]


def _decompress(data, encoding):
    if not data or not encoding: return data
    enc = encoding.lower()
    try:
        if "gzip" in enc: return gzip.decompress(data)
        if "deflate" in enc:
            try: return zlib.decompress(data)
            except zlib.error: return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception: pass
    return data


def _json_safe(v):
    if isinstance(v, list): return [_json_safe(x) for x in v]
    if isinstance(v, bytes):
        try:
            s = v.decode("utf-8")
            if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s): return s
        except Exception: pass
        return v.hex()
    if isinstance(v, (str, int, float, bool)) or v is None: return v
    return str(v)


def _pretty_flat(flat):
    out = {}
    for k, v in flat.items():
        if isinstance(v, bytes):
            try:
                s = v.decode("utf-8")
                if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s):
                    out[str(k)] = s; continue
            except Exception: pass
            out[str(k)] = v.hex()
        elif isinstance(v, list): out[str(k)] = [_json_safe(x) for x in v]
        else: out[str(k)] = _json_safe(v)
    return out


def _tree_to_json(tree):
    if not tree: return None
    out = []
    for num, wt, val, nested in tree:
        if wt == "MESSAGE":
            out.append({"field": num, "type": "MESSAGE", "size": val,
                        "nested": _tree_to_json(nested)})
        else: out.append({"field": num, "type": wt, "value": _json_safe(val)})
    return out



def crc7(buf, c=0):
    c &= 0x7F
    for b in buf: c = CRC7_TABLE[((2*c) ^ b) & 0xFF] & 0x7F
    return c


def tea_dec(v0, v1, k):
    s = (TEA_DELTA * TEA_ROUNDS) & TEA_M
    for _ in range(TEA_ROUNDS):
        v1 = (v1 - ((((v0<<4)+k[2])&TEA_M) ^ ((v0+s)&TEA_M) ^ ((v0>>5)+k[3]))) & TEA_M
        v0 = (v0 - ((((v1<<4)+k[0])&TEA_M) ^ ((v1+s)&TEA_M) ^ ((v1>>5)+k[1]))) & TEA_M
        s = (s - TEA_DELTA) & TEA_M
    return v0, v1


def tea_cbc_decrypt(body, key):
    k = struct.unpack('<4I', key)
    out = bytearray(len(body))
    prev_cipher = bytearray(8)
    prev_intermediate = bytearray(8)
    for i in range(0, len(body), 8):
        x = bytes(a ^ b for a, b in zip(body[i:i+8], prev_intermediate))
        d = struct.pack('<2I', *tea_dec(*struct.unpack('<2I', x), k))
        out[i:i+8] = bytes(a ^ b for a, b in zip(d, prev_cipher))
        prev_cipher[:] = body[i:i+8]
        prev_intermediate[:] = d
    return bytes(out)


def oicq_unpad(padded):
    if len(padded) < 8: return None
    if any(padded[-1-i] for i in range(7)): return None
    pad_len = padded[0] & 0x07
    s = 3 + pad_len
    e = len(padded) - 7
    return padded[s:e] if s < e else b""



# ═══════════════════════════════════════════════════════════════════
# CMD 448 — CS RANKED MATCH AUTH (packet crafting)
# ═══════════════════════════════════════════════════════════════════

UDP_DEVICE_ID    = b""
UDP_CLIENT_IP    = b""
UDP_DEVICE_HASH  = b""
SESSION_TOKEN    = b""
TOKEN_SPLIT      = 0
MSG_KEY_AUTH_448 = None

M448_B_HEAD = bytes.fromhex(
    "0000000000000001000000000000000000000000010000000000010000000003")
M448_B_TAIL = b"\x02\x00"
M448_A      = bytes.fromhex("01000000000000010202010104494e0002030001000004")


def varint(v):
    return _encode_varint(int(v) & 0xFFFFFFFFFFFFFFFF)


def zigzag_str(s):
    """length-prefixed string. FF uses zigzag-encoded length (=2*len for nonneg)."""
    if isinstance(s, str):
        s = s.encode("utf-8")
    n = len(s)
    return _encode_varint((n << 1) ^ (n >> 63)) + s


def _tea_enc(v0, v1, k):
    s = 0
    for _ in range(TEA_ROUNDS):
        s = (s + TEA_DELTA) & TEA_M
        v0 = (v0 + ((((v1 << 4) + k[0]) & TEA_M)
                    ^ ((v1 + s) & TEA_M)
                    ^ ((v1 >> 5) + k[1]))) & TEA_M
        v1 = (v1 + ((((v0 << 4) + k[2]) & TEA_M)
                    ^ ((v0 + s) & TEA_M)
                    ^ ((v0 >> 5) + k[3]))) & TEA_M
    return v0, v1


def tea_cbc_encrypt(plain, key):
    """FF-variant TEA CBC (matches tea_cbc_decrypt). plain must be 8-aligned."""
    if len(plain) % 8:
        raise ValueError("plaintext must be 8-byte aligned")
    k = struct.unpack('<4I', key)
    out = bytearray(len(plain))
    prev_cipher       = bytearray(8)
    prev_intermediate = bytearray(8)
    for i in range(0, len(plain), 8):
        D_i = bytes(a ^ b for a, b in zip(plain[i:i+8], prev_cipher))
        tea_out = struct.pack('<2I', *_tea_enc(*struct.unpack('<2I', D_i), k))
        C_i = bytes(a ^ b for a, b in zip(tea_out, prev_intermediate))
        out[i:i+8] = C_i
        prev_cipher[:]       = C_i
        prev_intermediate[:] = D_i
    return bytes(out)


def oicq_pad(data):
    """inverse of oicq_unpad: 1 marker byte + (2+pad_len) random + data + 7 zeros."""
    pad_len = (6 - len(data)) % 8
    first = ((pad_len & 0x07) | (os.urandom(1)[0] & 0xF8)) & 0xFF
    return bytes([first]) + os.urandom(2 + pad_len) + data + bytes(7)


def _encode_udp_header(fields, layout, k):
    """inverse of parse_udp_header. returns bytes(2 + sum(field sizes))."""
    v80 = ((k & 0xFF) << 8) | (k & 0xFF)
    out = bytearray([0x00, 0x00])
    for code in layout:
        n = UDP_FIELD_SIZES[code]
        v = fields.get(UDP_FIELD_NAMES[code], 0) or 0
        if n == 1:
            out.append((v ^ k) & 0xFF)
        else:
            v = (v ^ v80) & 0xFFFF
            out.append(v & 0xFF)
            out.append((v >> 8) & 0xFF)
    return bytes(out)


def build_pkt(cmd, body, key, mask, reliable=True, order_id=0,
              send_option=2, flags=1, msg_key=None, byte0=0x00):
    """Assemble a complete on-wire UDP packet. key = 16B TEA, mask = e.g. '01234'."""
    layout = [int(c) for c in mask]
    k = key[0]
    if flags & 1:
        enc_key = msg_key if msg_key is not None else key
        wire_body = tea_cbc_encrypt(oicq_pad(body), enc_key)
    else:
        wire_body = body

    fields = {
        "sendOption": send_option,
        "cmd":        cmd,
        "orderId":    order_id if reliable else 0,
        "flags":      flags,
        "length":     len(wire_body),
    }
    hdr = bytearray(_encode_udp_header(fields, layout, k))
    hdr[0] = byte0 & 0xFF
    hdr[1] = crc7(bytes(hdr[2:]) + wire_body) & 0x7F
    return bytes(hdr) + wire_body


def pkt_auth448(token=None, key=None, mask=None, player_id=0,
                match_id=0, client_version="1.108.1", order_id=1,
                flags_byte=0x0F, mode_id=6, session=0):
    """Craft a valid cmd-448 CS-ranked auth packet. Returns raw UDP bytes."""
    token = token if token is not None else SESSION_TOKEN
    key   = key   if key   is not None else (MSG_KEY_AUTH_448 or UDP_ACTIVE_KEY)
    mask  = mask  if mask  is not None else UDP_ACTIVE_LAYOUT_STR
    if not token or not key or not mask:
        raise ValueError("pkt_auth448: token/key/mask not set — call set_auth448_identity() first")

    body = (varint(player_id)
            + varint(match_id)
            + bytes([0x01, flags_byte & 0xFF])
            + varint(match_id)
            + M448_A
            + zigzag_str(client_version)
            + zigzag_str(UDP_DEVICE_ID)
            + M448_B_HEAD
            + bytes([mode_id & 0xFF, 0x00])
            + varint(session)
            + M448_B_TAIL
            + zigzag_str(UDP_CLIENT_IP)
            + zigzag_str(UDP_DEVICE_HASH)
            + zigzag_str(token[TOKEN_SPLIT:]))

    return build_pkt(448, body, key, mask, reliable=True, order_id=order_id,
                     send_option=2, flags=1, msg_key=MSG_KEY_AUTH_448)


def set_auth448_identity(device_id=None, client_ip=None, device_hash=None,
                         token=None, token_split=None, msg_key=None):
    global UDP_DEVICE_ID, UDP_CLIENT_IP, UDP_DEVICE_HASH
    global SESSION_TOKEN, TOKEN_SPLIT, MSG_KEY_AUTH_448
    if device_id   is not None: UDP_DEVICE_ID   = device_id.encode()   if isinstance(device_id, str)   else device_id
    if client_ip   is not None: UDP_CLIENT_IP   = client_ip.encode()   if isinstance(client_ip, str)   else client_ip
    if device_hash is not None: UDP_DEVICE_HASH = device_hash.encode() if isinstance(device_hash, str) else device_hash
    if token       is not None: SESSION_TOKEN   = token.encode()       if isinstance(token, str)       else token
    if token_split is not None: TOKEN_SPLIT     = int(token_split)
    if msg_key     is not None: MSG_KEY_AUTH_448 = msg_key
    print(f"{G}[auth448] identity: dev={len(UDP_DEVICE_ID)}B "
          f"ip={UDP_CLIENT_IP!r} hash={len(UDP_DEVICE_HASH)}B "
          f"token={len(SESSION_TOKEN)}B split={TOKEN_SPLIT}{RESET}")


def fire_auth448(target, **kwargs):
    """Build a 448 auth packet and send it to (ip, port)."""
    pkt = pkt_auth448(**kwargs)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(pkt, target)
        print(f"{G}[auth448] sent {len(pkt)}B → {target[0]}:{target[1]}{RESET}")
    finally:
        s.close()
    return pkt



def parse_udp_header(data, layout, k):
    v80 = (k << 8) | k; off = 2; f = {}
    for code in layout:
        n = UDP_FIELD_SIZES[code]
        if off + n > len(data): return None
        if n == 1: f[UDP_FIELD_NAMES[code]] = data[off] ^ k
        else: f[UDP_FIELD_NAMES[code]] = ((data[off] | data[off+1]<<8) ^ v80) & 0xFFFF
        off += n
    f["headerLen"] = off
    return f



# BRUTE-FORCE UDP HEADER DECODER (no key/mask required)
UDP_BRUTE_CANDIDATES = {}
UDP_BRUTE_CONFIRMED  = None


def _score_brute_candidate(k, layout, h, body, crc_ok_raw):
    score = 0
    if crc_ok_raw:
        score += 5
    if h["cmd"] in UDP_CMD_NAMES:
        score += 20
    if h["cmd"] in (1, 2, 3, 101, 447, 448, 849):
        score += 10
    encrypted = bool(h["flags"] & 1)
    if not encrypted:
        try:
            if _looks_like_proto(body):
                score += 15
                if parse_proto_flat(body):
                    score += 10
        except Exception:
            pass
    else:
        try:
            if not _looks_like_proto(body):
                score += 3
        except Exception:
            pass
    return score


def brute_force_udp_header(data):
    global UDP_BRUTE_CONFIRMED
    if len(data) < 8:
        return None
    crc_ok_raw = (data[1] & 0x7F) == crc7(data[2:])

    if UDP_BRUTE_CONFIRMED:
        k_hint, layout_str = UDP_BRUTE_CONFIRMED
        try:
            layout = [int(c) for c in layout_str]
            h = parse_udp_header(data, layout, k_hint)
            if h and h["flags"] <= 7 and h["sendOption"] <= 7 \
                    and h["length"] == len(data) - h["headerLen"]:
                body = data[h["headerLen"]:h["headerLen"]+h["length"]]
                score = _score_brute_candidate(k_hint, layout, h, body, crc_ok_raw)
                return (score + 100, k_hint, "RUDP", layout, h, crc_ok_raw)
        except Exception:
            pass

    candidates = []
    for k in range(256):
        for name, layout in all_udp_layouts():
            try:
                h = parse_udp_header(data, layout, k)
                if not h:
                    continue
                if h["flags"] > 7 or h["sendOption"] > 7:
                    continue
                if h["length"] != len(data) - h["headerLen"]:
                    continue
                body = data[h["headerLen"]:h["headerLen"]+h["length"]]
                score = _score_brute_candidate(k, layout, h, body, crc_ok_raw)
                candidates.append((score, k, name, layout, h, crc_ok_raw))
            except Exception:
                continue

    if not candidates:
        return None
    candidates.sort(key=lambda x: -x[0])
    best = candidates[0]

    layout_str = "".join(map(str, best[3]))
    vote_key = (best[1], layout_str)
    UDP_BRUTE_CANDIDATES[vote_key] = UDP_BRUTE_CANDIDATES.get(vote_key, 0) + 1
    if UDP_BRUTE_CANDIDATES[vote_key] >= 3 and UDP_BRUTE_CONFIRMED is None:
        UDP_BRUTE_CONFIRMED = vote_key
        print("[UDP] brute-force CONFIRMED: XOR=0x%02X layout=%s (locked for session)"
              % (best[1], layout_str))

    return best


def all_udp_layouts():
    return ([("RUDP", list(p)) for p in itertools.permutations(range(5))] +
            [("nonRUDP", list(p)) for p in itertools.permutations([0,1,3,4])])


def _attempt_udp_decode(data, key, name, layout, h, body):
    encrypted = bool(h["flags"] & 1)
    if encrypted:
        if len(body) < 8 or len(body) % 8 != 0: return None
        try:
            padded = tea_cbc_decrypt(body, key)
            content = oicq_unpad(padded)
            if content is None: return None
        except Exception:
            return None
    else:
        content = body

    result = {
        "decoded":     True,
        "key_used":    key.hex().upper(),
        "layout":      "".join(map(str, layout)),
        "type":        name,
        "cmd":         h["cmd"],
        "cmd_name":    UDP_CMD_NAMES.get(h["cmd"], f"cmd_{h['cmd']}"),
        "send_option": h["sendOption"],
        "order_id":    h.get("orderId"),
        "flags":       h["flags"],
        "encrypted":   encrypted,
        "crc7_ok":     ((data[1] & 0x7F) == crc7(data[2:])),
        "plain_hex":   content.hex(),
        "protobuf":    None,
        "error":       None,
    }
    try:
        tree = decode_protobuf_recursive(content)
        if tree: result["protobuf"] = _tree_to_json(tree)
    except Exception: pass
    return result


def decode_udp_packet(data):
    result = {
        "decoded": False, "key_used": None, "layout": None, "type": None,
        "cmd": None, "cmd_name": None, "send_option": None, "order_id": None,
        "flags": None, "encrypted": False, "crc7_ok": False,
        "plain_hex": None, "protobuf": None, "error": None, "brute": False,
    }
    try:
        if len(data) < 8:
            result["error"] = "too short"
            return result
        result["crc7_ok"] = ((data[1] & 0x7F) == crc7(data[2:]))

        with udp_key_lock:
            active_key        = UDP_ACTIVE_KEY
            active_layout_str = UDP_ACTIVE_LAYOUT_STR
            active_type       = UDP_ACTIVE_TYPE

        # PATH 1: known key + mask (authoritative)
        if active_key is not None and active_layout_str:
            try:
                layout = [int(c) for c in active_layout_str]
                h = parse_udp_header(data, layout, active_key[0])
                if h and h["flags"] <= 7 and h["sendOption"] <= 7 \
                        and h["length"] == len(data) - h["headerLen"]:
                    body = data[h["headerLen"]:h["headerLen"]+h["length"]]
                    r = _attempt_udp_decode(data, active_key, active_type or "RUDP",
                                            layout, h, body)
                    if r:
                        result.update(r)
                        return result
            except Exception:
                pass
            for name, layout in all_udp_layouts():
                try:
                    h = parse_udp_header(data, layout, active_key[0])
                    if not h:
                        continue
                    if h["flags"] > 7 or h["sendOption"] > 7:
                        continue
                    if h["length"] != len(data) - h["headerLen"]:
                        continue
                    body = data[h["headerLen"]:h["headerLen"]+h["length"]]
                    r = _attempt_udp_decode(data, active_key, name, layout, h, body)
                    if r:
                        result.update(r)
                        return result
                except Exception:
                    continue

        # PATH 1.5: cached brute key (fast path)
        global _CACHED_BRUTE_KEY, _CACHED_BRUTE_LAYOUT, _CACHED_BRUTE_NAME
        if _CACHED_BRUTE_KEY is not None and _CACHED_BRUTE_LAYOUT:
            try:
                h = parse_udp_header(data, _CACHED_BRUTE_LAYOUT, _CACHED_BRUTE_KEY)
                if h and h["flags"] <= 7 and h["sendOption"] <= 7 and h["length"] == len(data) - h["headerLen"]:
                    body = data[h["headerLen"]:h["headerLen"]+h["length"]]
                    encrypted = bool(h["flags"] & 1)
                    result.update({
                        "decoded": True, "brute": True,
                        "key_used": "CACHED_XOR=0x%02X" % _CACHED_BRUTE_KEY,
                        "layout": "".join(map(str, _CACHED_BRUTE_LAYOUT)),
                        "type": (_CACHED_BRUTE_NAME or "RUDP") + "(cached)",
                        "cmd": h["cmd"], "cmd_name": UDP_CMD_NAMES.get(h["cmd"], "cmd_%d" % h["cmd"]),
                        "send_option": h["sendOption"], "order_id": h.get("orderId"),
                        "flags": h["flags"], "encrypted": encrypted,
                    })
                    if not encrypted:
                        result["plain_hex"] = body.hex()
                    return result
            except Exception:
                pass

        # PATH 2: brute-force (no key/mask needed)
        bf = brute_force_udp_header(data)
        if bf:
            _CACHED_BRUTE_KEY = bf[1]
            _CACHED_BRUTE_NAME = bf[2]
            _CACHED_BRUTE_LAYOUT = bf[3]
        if bf:
            score, k, name, layout, h, crc_ok = bf
            body = data[h["headerLen"]:h["headerLen"]+h["length"]]
            encrypted = bool(h["flags"] & 1)
            result.update({
                "decoded":     True,
                "brute":       True,
                "key_used":    "BRUTE_XOR=0x%02X" % k,
                "layout":      "".join(map(str, layout)),
                "type":        name + "(brute)",
                "cmd":         h["cmd"],
                "cmd_name":    UDP_CMD_NAMES.get(h["cmd"], "cmd_%d" % h["cmd"]),
                "send_option": h["sendOption"],
                "order_id":    h.get("orderId"),
                "flags":       h["flags"],
                "encrypted":   encrypted,
            })
            if not encrypted:
                result["plain_hex"] = body.hex()
                try:
                    tree = decode_protobuf_recursive(body)
                    if tree:
                        result["protobuf"] = _tree_to_json(tree)
                except Exception:
                    pass
            else:
                result["error"] = "header OK (brute); payload encrypted - TEA key required"
            return result

        result["error"] = "no layout matched (brute-force exhausted)"
    except Exception as e:
        result["error"] = "exception: %s" % e
    return result



def extract_udp_info_from_match_frame(body):

    info = {"server": None, "key": None, "key_hex": None,
            "mask": None, "all_keys": [], "all_masks": []}
    try:
        tree = decode_protobuf_recursive(body)
    except Exception:
        tree = []

    def add_key(kb):
        if kb and len(kb) == 16 and kb not in info["all_keys"]:
            info["all_keys"].append(kb)
            if info["key"] is None:
                info["key"] = kb
                info["key_hex"] = kb.hex().upper()

    def walk(fields, depth=0):
        if depth > 12: return
        for num, wt, val, nested in fields:
            if wt == "STRING":
                if info["server"] is None:
                    try:
                        if _IPPORT_RE.match(val.encode("utf-8", "ignore")):
                            info["server"] = val
                    except Exception: pass
                if _HEX16_RE.match(val):
                    try: add_key(bytes.fromhex(val))
                    except Exception: pass
                if _MASK_RE.match(val) and sorted(val) == sorted("01234"):
                    if val not in info["all_masks"]:
                        info["all_masks"].append(val)
                    if info["mask"] is None:
                        info["mask"] = val
            elif wt == "BYTES":
                try: raw = bytes.fromhex(val)
                except Exception: raw = b""
                if raw:
                    if _IPPORT_RE.match(raw) and info["server"] is None:
                        try: info["server"] = raw.decode("utf-8", "ignore")
                        except Exception: pass
                    elif len(raw) == 16: add_key(raw)
                    elif len(raw) == 32:
                        add_key(raw[:16]); add_key(raw[16:])
            elif wt == "MESSAGE" and nested:
                walk(nested, depth + 1)

    walk(tree)
    return info


def set_udp_session_key(key, mask, server, source):
    global UDP_ACTIVE_KEY, UDP_ACTIVE_LAYOUT_STR, UDP_ACTIVE_TYPE
    global MSG_KEY_AUTH_448
    changed = False
    with udp_key_lock:
        if UDP_ACTIVE_KEY != key or UDP_ACTIVE_LAYOUT_STR != mask:
            UDP_ACTIVE_KEY        = key
            UDP_ACTIVE_LAYOUT_STR = mask
            UDP_ACTIVE_TYPE       = "RUDP"
            if MSG_KEY_AUTH_448 is None:
                MSG_KEY_AUTH_448 = key
            changed = True
    if not changed:
        return

    with udp_keys_lock:
        udp_keys_history.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "source":    source,
            "key_hex":   key.hex().upper(),
            "mask":      mask,
            "server":    server,
        })
    save_udp_keys(force=True)

    print(f"\n{BOLD}{G}╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  🔑  UDP KEY + MASK LOADED  ({source})")
    print(f"╠══════════════════════════════════════════════════════════════════╣")
    print(f"║  KEY  : {key.hex().upper()}")
    print(f"║  MASK : {mask}")
    print(f"║  SERVER: {server}")
    print(f"║  → saved to {os.path.abspath(UDP_KEYS_FILE)}")
    print(f"╚══════════════════════════════════════════════════════════════════╝{RESET}\n")



def intercept_major_login_request(body):
    if not body or len(body) < 16 or len(body) % 16 != 0: return body, None
    plain = aes_decrypt(body, AES_KEY, AES_IV)
    if plain is None: return body, None
    parsed = parse_proto_flat(plain)
    old_val = parsed.get(20)
    if isinstance(old_val, list): old_val = old_val[-1] if old_val else None
    old_str = None
    if isinstance(old_val, bytes):
        try: old_str = old_val.decode("utf-8", "ignore")
        except Exception: old_str = old_val.hex()
    elif isinstance(old_val, int): old_str = str(old_val)
    new_plain = replace_fields_in_proto(plain, {20: MODIFIED_FIELD_20_VALUE})
    if new_plain == plain: return body, None
    try: new_body = aes_encrypt(new_plain, AES_KEY, AES_IV)
    except Exception: return body, None
    return new_body, {"old_field_20": old_str, "new_field_20": MODIFIED_FIELD_20_VALUE,
                      "orig_len": len(body), "new_len": len(new_body)}


def _encode_tag(field, wire):
    v = (field << 3) | wire; out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); return bytes(out)


def _scan_blob16(blob, field):
    if not blob: return None
    tag = _encode_tag(field, 2); tl = len(tag); last = None
    i, n = 0, len(blob)
    while i <= n - tl - 1:
        if blob[i:i+tl] != tag: i += 1; continue
        try: length, after = _read_varint(blob, i + tl)
        except Exception: i += 1; continue
        if length == 16 and after + 16 <= n: last = blob[after:after+16]
        i += 1
    return last


def _last_value(v):
    return v[-1] if isinstance(v, list) and v else v if not isinstance(v, list) else None


def _blob16(fields, num):
    v = _last_value(fields.get(num))
    return v if isinstance(v, bytes) and len(v) == 16 else None


def _try_parse_keys(raw):
    if not raw or len(raw) < 32: return None, None, None
    try:
        f = parse_proto_flat(raw)
        k, v = _blob16(f, 22), _blob16(f, 23)
        if k and v: return k, v, "parse@0"
    except Exception: pass
    k, v = _scan_blob16(raw, 22), _scan_blob16(raw, 23)
    if k and v: return k, v, "scan@0"
    if len(raw) > MAJOR_LOGIN_OFFSET:
        blob = raw[MAJOR_LOGIN_OFFSET:]
        try:
            f = parse_proto_flat(blob)
            k2, v2 = _blob16(f, 22), _blob16(f, 23)
            if k2 and v2: return k2, v2, "parse@64"
        except Exception: pass
        k2, v2 = _scan_blob16(blob, 22), _scan_blob16(blob, 23)
        if k2 and v2: return k2, v2, "scan@64"
    return None, None, None


def parse_major_login_response(raw, encoding=""):
    if not raw: return None, None, None
    dec = _decompress(raw, encoding) if encoding else raw
    for candidate, tag in ((dec, "" if dec is raw else "+gzip"), (raw, "")):
        k, v, s = _try_parse_keys(candidate)
        if k and v: return k, v, s + tag
    return None, None, None


def set_session_keys(key, iv, source):
    global SESSION_KEY, SESSION_IV, SESSION_READY
    with session_lock:
        SESSION_KEY, SESSION_IV, SESSION_READY = key, iv, True
    with keys_lock:
        session_keys_history.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "source": source,
            "key_hex": key.hex().upper(), "iv_hex": iv.hex().upper(),
            "key_b64": __import__("base64").b64encode(key).decode(),
            "iv_b64": __import__("base64").b64encode(iv).decode(),
        })
    save_keys(force=True)
    print(f"\n{BOLD}{G}╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  🔑  SESSION KEYS LOADED  ({source})")
    print(f"║  KEY : {key.hex().upper()}")
    print(f"║  IV  : {iv.hex().upper()}")
    print(f"╚══════════════════════════════════════════════════════════════════╝{RESET}\n")


def try_decrypt_login(raw):
    p = parse_proto_flat(raw)
    v14 = p.get(14)
    if isinstance(v14, bytes) and b":" in v14: return raw, False, p
    dec = aes_decrypt(raw)
    if dec:
        p = parse_proto_flat(dec); v14 = p.get(14)
        if isinstance(v14, bytes) and b":" in v14: return dec, True, p
    return raw, False, {}


def _extract_target(parsed, num):
    v = parsed.get(num)
    if isinstance(v, list): v = v[0] if v else b""
    if isinstance(v, bytes):
        try: v = v.decode("utf-8", "ignore")
        except Exception: v = ""
    if not v or ":" not in str(v): return None
    try:
        ip, port = str(v).rsplit(":", 1)
        return (ip.strip(), int(port))
    except Exception: return None


def rewrite_getlogindata(raw):
    plain, was_enc, parsed = try_decrypt_login(raw)
    real_online = _extract_target(parsed, 14)
    real_chat = _extract_target(parsed, 32)
    if not real_online: return raw, None, None
    replaced = replace_fields_in_proto(plain, {
        14: f"127.0.0.1:{TCP_ONLINE_PORT}".encode(),
        32: f"127.0.0.1:{TCP_CHAT_PORT}".encode(),
    })
    if was_enc:
        try: replaced = aes_encrypt(replaced)
        except Exception: pass
    return replaced, real_online, real_chat



def handle_match_frame(frame, direction="S2C"):
    if direction != "S2C":
        return None
    if len(frame) < 5:
        return None

    ftype = frame[:2].hex()
    if ftype not in MATCH_FRAME_TYPES:
        return None

    body = frame[5:]
    print(f"\n{Y}[{ftype} S2C] received  body={len(body)}B  "
          f"── PLAIN protobuf, no AES ──{RESET}")


    try:
        info = extract_udp_info_from_match_frame(body)
        if info["key"] and info["mask"]:
            real_server = info["server"] or "?"
            set_udp_session_key(info["key"], info["mask"], real_server, f"{ftype} frame")
        elif info["key"]:
            print(f"{Y}[{ftype}] UDP key found but no mask — decoder inactive{RESET}")
        elif info["mask"]:
            print(f"{Y}[{ftype}] UDP mask found but no key — decoder inactive{RESET}")
        else:
            print(f"{Y}[{ftype}] no UDP key/mask in this frame{RESET}")
    except Exception as e:
        print(f"{R}[{ftype}] udp info extract error: {e}{RESET}")
        info = {"server": None, "key": None, "key_hex": None, "mask": None}

    # ── 2. rewrite ip:port → LOCAL_MATCH_ADDR ──
    rewritten, old = _rewrite_ip_port_deep(body, LOCAL_MATCH_ADDR.encode())
    if old is None:
        print(f"{Y}[{ftype} S2C] no ip:port string in body — forwarding unchanged{RESET}")
        return None
    if not _looks_like_proto(rewritten):
        print(f"{R}[{ftype} S2C] ⚠ rewritten body is not valid protobuf — aborting{RESET}")
        return None

    old_str = old.decode("utf-8", "ignore")
    try:
        ip, port = old_str.rsplit(":", 1)
        real_match = (ip.strip(), int(port))
    except Exception:
        print(f"{R}[{ftype} S2C] invalid address: {old_str!r}{RESET}")
        return None
    if len(rewritten) > 0xFFFFFF:
        return None

    new_frame = (bytes.fromhex(ftype)
                 + len(rewritten).to_bytes(3, "big")
                 + rewritten)

    with state_lock:
        global MATCH_TARGET
        MATCH_TARGET = real_match

    print(f"\n{BOLD}{G}{'═' * 74}{RESET}")
    print(f"{BOLD}{G}  ★★★  {ftype} S2C — PLAIN REWRITE  ★★★{RESET}")
    print(f"{BOLD}{G}{'═' * 74}{RESET}")
    print(f"{G}  frame type        : {ftype}  (plain protobuf){RESET}")
    print(f"{G}  original server   : {old_str}{RESET}")
    print(f"{G}  replaced with     : {LOCAL_MATCH_ADDR}{RESET}")
    print(f"{G}  encryption        : NONE — {ftype} is plain protobuf{RESET}")
    print(f"{G}  body length       : {len(body)} → {len(rewritten)}B "
          f"(Δ {len(rewritten)-len(body):+d}){RESET}")
    print(f"{G}  UDP relay target  : {real_match[0]}:{real_match[1]}{RESET}")
    if info.get("key_hex"):
        print(f"{G}  udp key           : {info['key_hex']}{RESET}")
    if info.get("mask"):
        print(f"{G}  udp mask          : {info['mask']}{RESET}")

    print(f"\n{Y}  ── protobuf after rewrite ──{RESET}")
    tree = decode_protobuf_recursive(rewritten)
    for ln in format_protobuf_tree(tree, indent="    "):
        print(f"{Y}{ln}{RESET}")
    print(f"{BOLD}{G}{'═' * 74}{RESET}\n")

    ensure_udp_relay()
    save_tcp(force=True)
    return new_frame



import queue

udp_log_queue = queue.Queue(maxsize=10000)
_CACHED_BRUTE_KEY = None
_CACHED_BRUTE_LAYOUT = None
_CACHED_BRUTE_NAME = None

def _log_udp_worker():
    while True:
        try:
            item = udp_log_queue.get()
            if not item: continue
            direction, data, frm, to = item
            _log_udp(direction, data, frm, to)
        except Exception:
            time.sleep(0.01)

threading.Thread(target=_log_udp_worker, daemon=True).start()

def ensure_udp_relay():
    global UDP_RELAY_SOCK
    with udp_sock_lock:
        if UDP_RELAY_SOCK is not None: return True
        for addr in [("0.0.0.0", UDP_MATCH_PORT), ("127.0.0.1", UDP_MATCH_PORT)]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(addr)
                UDP_RELAY_SOCK = sock
                threading.Thread(target=udp_relay_loop, args=(sock,), daemon=True).start()
                print(f"{G}✅ [UDP] relay bound on {addr[0]}:{addr[1]}{RESET}")
                return True
            except Exception as e:
                print(f"{Y}[UDP] bind {addr[0]}:{addr[1]} failed: {e}{RESET}")
                try: sock.close()
                except Exception: pass
        print(f"{R}❌ [UDP] could not bind port {UDP_MATCH_PORT}{RESET}")
        return False


def udp_relay_loop(srv):
    global UDP_PACKETS_RECEIVED
    sessions = {}
    while True:
        try:
            data, client = srv.recvfrom(131072)
        except Exception as e:
            print(f"{R}[UDP] recv error: {e}{RESET}")
            break

        UDP_PACKETS_RECEIVED += 1
        with state_lock:
            real = MATCH_TARGET

        if not real:
            continue
        if real[0] == "127.0.0.1" and real[1] == UDP_MATCH_PORT:
            continue

        up_info = sessions.get(client)
        if up_info is None or up_info[1] != real:
            if up_info is not None:
                try: up_info[0].close()
                except Exception: pass
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
            up.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
            up.settimeout(120)
            sessions[client] = (up, real)
            threading.Thread(target=_udp_upstream_reader,
                             args=(up, srv, client), daemon=True).start()
            print(f"{G}  ✅ new session: {client[0]}:{client[1]} → {real[0]}:{real[1]}{RESET}")
        else:
            up = up_info[0]

        # 1. IMMEDIATE FORWARD FIRST (sub-ms wire delivery)
        try:
            up.sendto(data, real)
        except Exception as e:
            print(f"{R}  ⚠ UDP forward error: {e}{RESET}")

        # 2. Async non-blocking log
        try:
            udp_log_queue.put_nowait(("C2S", data, client, real))
        except queue.Full:
            pass


def _udp_upstream_reader(up, srv, client):
    while True:
        try:
            data, addr = up.recvfrom(131072)
        except socket.timeout:
            try: up.close()
            except Exception: pass
            return
        except Exception as e:
            return

        try:
            srv.sendto(data, client)
        except Exception as e:
            return

        try:
            udp_log_queue.put_nowait(("S2C", data, addr, client))
        except queue.Full:
            pass


def _log_udp(direction, data, frm, to):
    key = f"udp_{direction.lower()}"
    counters[key] += 1
    seq = counters[key]
    ts = time.strftime("%H:%M:%S") + f".{int((time.time() % 1) * 1000):03d}"
    col = Y if direction == "C2S" else B
    to_str = f"{to[0]}:{to[1]}" if to and to[0] else "?"

    print(f"\n{col}{BOLD}{'═' * 74}{RESET}")
    print(f"{col}{BOLD}  UDP {direction} #{seq:<4} {ts} len={len(data)}B{RESET}")
    print(f"{col}{BOLD}  {frm[0]}:{frm[1]} → {to_str}{RESET}")
    print(f"{col}{BOLD}{'═' * 74}{RESET}")
    for line in hex_lines(data, 32):
        print(f"{col}      {line}{RESET}")

    decoded = decode_udp_packet(data)
    if decoded["decoded"]:
        print(f"\n{G}{BOLD}  ── decoded ──{RESET}")
        print(f"{G}  key       : {decoded['key_used']}{RESET}")
        print(f"{G}  layout    : {decoded['layout']}   type: {decoded['type']}{RESET}")
        print(f"{G}  cmd       : {decoded['cmd']}  ({decoded['cmd_name']}){RESET}")
        print(f"{G}  flags     : {decoded['flags']}  "
              f"({'encrypted' if decoded['encrypted'] else 'plain'}){RESET}")
        print(f"{G}  crc7      : {'OK' if decoded['crc7_ok'] else 'BAD'}{RESET}")
        if decoded.get("brute"):
            print(f"{M}  source    : BRUTE-FORCED (no key/mask needed){RESET}")
        if decoded.get("error"):
            print(f"{Y}  [!] {decoded['error']}{RESET}")
        if decoded.get("plain_hex"):
            pb = bytes.fromhex(decoded["plain_hex"])
            print(f"\n{M}  [decrypted] ({len(pb)}B){RESET}")
            for line in hex_lines(pb, 32):
                print(f"{M}      {line}{RESET}")
            try:
                ptree = decode_protobuf_recursive(pb)
                if ptree:
                    print(f"\n{Y}  ── protobuf (decoded) ──{RESET}")
                    for ln in format_protobuf_tree(ptree, indent="    "):
                        print(f"{Y}{ln}{RESET}")
            except Exception: pass
    else:
        print(f"\n{Y}  ── decode: {decoded.get('error')} ──{RESET}")
    print(f"{col}{'─' * 74}{RESET}")

    udp_capture.append({
        "seq": seq, "timestamp": time.strftime("%Y-%m-%dT") + ts,
        "channel": "udp", "direction": direction,
        "from": f"{frm[0]}:{frm[1]}", "to": to_str,
        "length": len(data), "packet_hex": data.hex(),
    })
    save_udp()

    if decoded["decoded"]:
        dec_entry = {
            "seq": seq, "timestamp": time.strftime("%Y-%m-%dT") + ts,
            "direction": direction,
            "from": f"{frm[0]}:{frm[1]}", "to": to_str,
            "length": len(data), "packet_hex": data.hex(),
            "decoded": decoded,
        }
        with udp_decoded_lock:
            udp_decoded.append(dec_entry)
        save_udp_decoded()


# ============================================================
# HTTP proxy
# ============================================================
class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.22.1"
    sys_version = ""
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()

    def do_CONNECT(self):
        target = self.path
        host, _, port_s = target.partition(":")
        try: port = int(port_s)
        except Exception: port = 443
        try: upstream = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            print(f"{R}[CONNECT] {target}: {e}{RESET}")
            self.send_error(502); return
        self.send_response(200, "Connection established")
        self.end_headers()
        try:
            self.connection.setblocking(True); upstream.setblocking(True)
            self._tunnel(self.connection, upstream)
            self._tunnel(upstream, self.connection)
        finally:
            try: upstream.close()
            except Exception: pass

    @staticmethod
    def _tunnel(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d: break
                dst.sendall(d)
        except Exception: pass

    def _handle(self):
        t0 = time.time()
        counters["http_req"] += 1
        seq = counters["http_req"]
        raw_path = self.path
        if raw_path.startswith(("http://", "https://")):
            parsed = urlparse(raw_path)
            path_only = parsed.path or "/"
            url_host = parsed.netloc.split(":")[0]
        else:
            path_only = raw_path.split("?", 1)[0]; url_host = None
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        hdr_host = self.headers.get("Host", "-")
        print(f"\n{BOLD}{C}▶ [{seq:04d}] {self.command} {raw_path}{RESET}")
        print(f"   {B}Host: {hdr_host}   Route: {path_only}{RESET}")
        if body: print(f"   {Y}Body({len(body)}B) {body[:64].hex()}…{RESET}")
        req_headers = {str(k): str(v) for k, v in self.headers.items()}
        http_entry = {"seq": seq, "type": "http",
                      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "request": {"method": self.command, "path": raw_path,
                                  "path_only": path_only, "host": hdr_host,
                                  "headers": req_headers, "body_hex": body.hex()}}
        with http_lock: http_capture.append(http_entry)

        send_body = body
        # [SAFE MODE] Do not modify client IP (field 20) in MajorLogin.

        status, wire_body, resp_headers = self._forward(send_body, path_only, raw_path, url_host)
        enc = (resp_headers or {}).get("Content-Encoding", "")
        dec_body = _decompress(wire_body, enc) if wire_body else wire_body
        print(f"   {DIM}← {status}  wire={len(wire_body)}B  dec={len(dec_body)}B{RESET}")

        if path_only.endswith("/MajorLogin") and status == 200:
            try:
                k, v, src = parse_major_login_response(dec_body)
                if not (k and v) and dec_body is not wire_body:
                    k, v, src = parse_major_login_response(wire_body)
                if k and v: set_session_keys(k, v, src)
            except Exception as e: print(f"{R}[MajorLogin] key parse error: {e}{RESET}")

        send_wire = wire_body; strip_enc = False
        if path_only.endswith("/GetLoginData") and status == 200:
            try:
                new_dec, online_t, chat_t = rewrite_getlogindata(dec_body)
                if online_t:
                    global ONLINE_TARGET, CHAT_TARGET
                    with state_lock:
                        ONLINE_TARGET = online_t; CHAT_TARGET = chat_t
                    send_wire = new_dec; strip_enc = True
                    print(f"{G}[GetLoginData] online={online_t} chat={chat_t}{RESET}")
            except Exception as e: print(f"{R}[GetLoginData] error: {e}{RESET}")

        http_entry["response"] = {"status": status,
            "headers": {str(k): str(v) for k, v in (resp_headers or {}).items()},
            "body_hex": send_wire.hex() if send_wire else "",
            "duration_ms": round((time.time() - t0) * 1000, 2)}

        self.send_response(status)
        for h, v in (resp_headers or {}).items():
            hl = h.lower()
            if hl in ("content-length", "connection", "transfer-encoding"): continue
            if hl == "content-encoding" and strip_enc: continue
            self.send_header(h, v)
        self.send_header("Content-Length", str(len(send_wire)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and send_wire: self.wfile.write(send_wire)
        save_http()

    def _resolve_host(self, path_only, url_host):
        if path_only in ROUTE_BY_PATH: return ROUTE_BY_PATH[path_only]
        for p, h in ROUTE_BY_PATH.items():
            if path_only.startswith(p): return h
        if url_host and url_host not in ("127.0.0.1", "localhost", "0.0.0.0"):
            return url_host
        hdr_host = self.headers.get("Host", "").split(":")[0]
        if hdr_host and hdr_host not in ("127.0.0.1", "localhost", "0.0.0.0"):
            return hdr_host
        return DEFAULT_HOST

    def _forward(self, body, path_only, raw_path, url_host):
        host = self._resolve_host(path_only, url_host)
        if raw_path.startswith(("http://", "https://")):
            p = urlparse(raw_path)
            rel_path = p.path or "/"
            if p.query:
                rel_path += "?" + p.query
        else:
            rel_path = raw_path
        url = f"https://{host}{rel_path}"
        headers = dict(self.headers)
        for h in ("connection","keep-alive","proxy-authenticate","proxy-authorization",
                  "te","trailers","transfer-encoding","upgrade"):
            headers.pop(h, None)
        headers["Host"] = host; headers.pop("Content-Length", None)
        try:
            req = urllib.request.Request(url, data=body if body else None, headers=headers)
            req.get_method = lambda: self.command
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=20, context=ctx)
            return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            raw = e.read() if hasattr(e, "read") else b""
            return e.code, raw, dict(e.headers) if hasattr(e, "headers") else {}
        except Exception as e:
            print(f"{R}   forward error: {e}{RESET}")
            return 502, b"", {}

    def log_message(self, *a): pass



def _try_plain_frame(data):
    if len(data) < 5: return None
    ftype = data[:2].hex()
    if ftype not in MATCH_FRAME_TYPES: return None
    declared = int.from_bytes(data[2:5], "big")
    if declared != len(data) - 5: return None
    return ftype, data[5:]


def decode_c2s(data):
    res = {"aes_used": None, "plain_hex": None, "plain_bytes": None,
           "protobuf_flat": None, "protobuf_tree": None}
    pm = _try_plain_frame(data)
    if pm and _looks_like_proto(pm[1]):
        ftype, body = pm
        res.update({"aes_used": f"PLAIN {ftype}@{len(body)}B",
                    "plain_hex": body.hex(), "plain_bytes": body,
                    "protobuf_flat": _pretty_flat(parse_proto_flat(body)),
                    "protobuf_tree": decode_protobuf_recursive(body)})
        return res
    with session_lock:
        ready, sk, sv = SESSION_READY, SESSION_KEY, SESSION_IV
    if ready:
        for off in AES_OFFSETS:
            pt = _try_aes_at(data, sk, sv, off)
            if pt:
                res.update({"aes_used": f"SESSION@{off}", "plain_hex": pt.hex(),
                            "plain_bytes": pt,
                            "protobuf_flat": _pretty_flat(parse_proto_flat(pt)),
                            "protobuf_tree": decode_protobuf_recursive(pt)})
                return res
    for off in AES_OFFSETS:
        pt = _try_aes_at(data, AES_KEY, AES_IV, off)
        if pt:
            res.update({"aes_used": f"STATIC@{off}", "plain_hex": pt.hex(),
                        "plain_bytes": pt,
                        "protobuf_flat": _pretty_flat(parse_proto_flat(pt)),
                        "protobuf_tree": decode_protobuf_recursive(pt)})
            return res
    return res


def decode_s2c(data):
    res = {"aes_used": None, "plain_hex": None, "plain_bytes": None,
           "protobuf_flat": None, "protobuf_tree": None}
    pm = _try_plain_frame(data)
    if pm and _looks_like_proto(pm[1]):
        ftype, body = pm
        res.update({"aes_used": f"PLAIN {ftype}@{len(body)}B",
                    "plain_hex": body.hex(), "plain_bytes": body,
                    "protobuf_flat": _pretty_flat(parse_proto_flat(body)),
                    "protobuf_tree": decode_protobuf_recursive(body)})
        return res
    if _looks_like_proto(data):
        res.update({"aes_used": "raw proto", "plain_hex": data.hex(),
                    "plain_bytes": data,
                    "protobuf_flat": _pretty_flat(parse_proto_flat(data)),
                    "protobuf_tree": decode_protobuf_recursive(data)})
        return res
    with session_lock:
        ready, sk, sv = SESSION_READY, SESSION_KEY, SESSION_IV
    if ready:
        for off in AES_OFFSETS:
            pt = _try_aes_at(data, sk, sv, off)
            if pt:
                res.update({"aes_used": f"SESSION@{off}", "plain_hex": pt.hex(),
                            "plain_bytes": pt,
                            "protobuf_flat": _pretty_flat(parse_proto_flat(pt)),
                            "protobuf_tree": decode_protobuf_recursive(pt)})
                return res
    for off in AES_OFFSETS:
        pt = _try_aes_at(data, AES_KEY, AES_IV, off)
        if pt:
            res.update({"aes_used": f"STATIC@{off}", "plain_hex": pt.hex(),
                        "plain_bytes": pt,
                        "protobuf_flat": _pretty_flat(parse_proto_flat(pt)),
                        "protobuf_tree": decode_protobuf_recursive(pt)})
            return res
    return res


def log_tcp(label, direction, data):
    if len(data) >= 2 and data[:2].hex() in SKIP_PACKET_TYPES: return
    key = f"{label}_{direction.lower()}"
    counters[key] += 1
    seq = counters[key]
    ptype = data[:2].hex() if len(data) >= 2 else "??"
    col = Y if direction == "C2S" else B
    dec = decode_c2s(data) if direction == "C2S" else decode_s2c(data)

    print(f"\n{col}{BOLD}{'═' * 74}{RESET}")
    print(f"{col}{BOLD}  {label.upper():<7} {direction} #{seq:<4} "
          f"type={ptype} len={len(data)}B{RESET}")
    print(f"{col}{BOLD}{'═' * 74}{RESET}")
    print(f"{BOLD}{G}  decode: {dec['aes_used'] or '-'}{RESET}")

    if dec["plain_hex"]:
        print(f"\n{M}  [plain] ({len(dec['plain_bytes'])}B){RESET}")
        for line in hex_lines(dec["plain_bytes"], 32):
            print(f"{M}      {line}{RESET}")
    if dec["protobuf_tree"]:
        print(f"\n{Y}  [protobuf]{RESET}")
        for ln in format_protobuf_tree(dec["protobuf_tree"], indent="      "):
            print(f"{Y}{ln}{RESET}")
    print(f"{col}{'─' * 74}{RESET}")

    tcp_capture.append({
        "seq": seq, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "channel": label, "direction": direction, "type": ptype,
        "length": len(data), "packet_hex": data.hex(),
        "decode": dec["aes_used"], "plain_hex": dec["plain_hex"],
        "protobuf_flat": dec["protobuf_flat"],
        "protobuf_tree": _tree_to_json(dec["protobuf_tree"]),
    })
    save_tcp()


async def tcp_pipe(reader, writer, label, direction,
                   s2c_hook=None, c2s_hook=None):
    buffer = bytearray()
    MAX_BUFFER = 200_000
    try:
        while True:
            data = await reader.read(65536)
            if not data: break
            buffer.extend(data)

            while len(buffer) > 0:
                if len(buffer) < 2: break
                ftype = buffer[:2].hex()

                if ftype not in MATCH_FRAME_TYPES:
                    chunk = bytes(buffer)
                    buffer.clear()
                    writer.write(chunk); await writer.drain()
                    if len(chunk) >= 2:
                        threading.Thread(target=log_tcp, args=(label, direction, chunk), daemon=True).start()
                    break

                if len(buffer) < 5: break
                declared = int.from_bytes(buffer[2:5], "big")
                if declared > 0x100000 or len(buffer) > MAX_BUFFER:
                    chunk = bytes(buffer); buffer.clear()
                    writer.write(chunk); await writer.drain()
                    break
                if len(buffer) < 5 + declared: break

                frame = bytes(buffer[:5 + declared])
                del buffer[:5 + declared]
                hook = s2c_hook if direction == "S2C" else c2s_hook
                if hook:
                    try: nf = hook(frame, direction)
                    except TypeError: nf = hook(frame)
                    if nf is not None: frame = nf
                writer.write(frame); await writer.drain()
                threading.Thread(target=log_tcp, args=(label, direction, frame), daemon=True).start()
    except (ConnectionResetError, BrokenPipeError): pass
    except asyncio.CancelledError: raise
    except Exception as e: print(f"{R}[{label}] pipe {direction}: {e}{RESET}")
    finally:
        if buffer:
            try:
                writer.write(bytes(buffer)); await writer.drain()
            except Exception: pass
        try: writer.close()
        except Exception: pass


async def handle_conn(local_r, local_w, real_ip, real_port, label,
                      s2c_hook=None, c2s_hook=None):
    try:
        rem_r, rem_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, real_port), timeout=10)
    except Exception as e:
        print(f"{R}[{label}] cannot reach {real_ip}:{real_port}: {e}{RESET}")
        try: local_w.close()
        except Exception: pass
        return
    t1 = asyncio.create_task(tcp_pipe(local_r, rem_w, label, "C2S", c2s_hook=c2s_hook))
    t2 = asyncio.create_task(tcp_pipe(rem_r, local_w, label, "S2C", s2c_hook=s2c_hook))
    try: await asyncio.gather(t1, t2)
    finally:
        for t in (t1, t2):
            if not t.done(): t.cancel()
        try: local_w.close()
        except Exception: pass
        try: rem_w.close()
        except Exception: pass
        save_tcp(force=True)


async def tcp_server(host, port, label, s2c_hook=None, c2s_hook=None):
    async def _on_client(r, w):
        target = None
        for _ in range(20):
            with state_lock:
                target = ONLINE_TARGET if label == "online" else CHAT_TARGET
            if target:
                break
            await asyncio.sleep(0.5)
        if not target:
            try: w.close()
            except Exception: pass
            return
        await handle_conn(r, w, target[0], target[1], label,
                          s2c_hook=s2c_hook, c2s_hook=c2s_hook)
    srv = await asyncio.start_server(_on_client, host, port)
    print(f"{G}✅ TCP [{label}] listening on {host}:{port}{RESET}")
    async with srv: await srv.serve_forever()


async def tcp_loop():
    await asyncio.gather(
        tcp_server("0.0.0.0", TCP_ONLINE_PORT, "online",
                   s2c_hook=handle_match_frame,
                   c2s_hook=handle_match_frame),
        tcp_server("0.0.0.0", TCP_CHAT_PORT, "chat"),
    )


def run_http():
    global HTTP_SERVER_REF
    try:
        HTTP_SERVER_REF = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ProxyHandler)
        HTTP_SERVER_REF.daemon_threads = True
        HTTP_SERVER_REF.handle_error = lambda *a: None
        print(f"{G}✅ HTTP proxy listening on 127.0.0.1:{HTTP_PORT}{RESET}")
        HTTP_SERVER_REF.serve_forever()
    except Exception as e: print(f"{R}HTTP error: {e}{RESET}")


def run_tcp():
    try: asyncio.run(tcp_loop())
    except Exception as e: print(f"{R}TCP error: {e}{RESET}")


def main():
    global _installed_paths

    _installed_paths = []
    load_existing()
    _installed_paths = install_localconfig()

    def _cleanup():
        save_all(force=True)
        remove_localconfig(_installed_paths)

    atexit.register(_cleanup)
    signal.signal(signal.SIGINT, lambda s, f: ( _cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: ( _cleanup(), sys.exit(0)))

    print(f"\n{BOLD}{Y}")
    print("  ╭──────────────────────────────────────────────────────────╮")
    print(f"  │                  {BOLD}{C}SHAHIL{Y}                       │")
    print("  │                                                          │")
    print(f"  │             {W}FREE FIRE NETWORK MONITOR{Y}                  │")
    print("  ╰──────────────────────────────────────────────────────────╯")
    print(f"{RESET}")

    print(f"{BOLD}{Y}  OUTPUT FILES{RESET}")
    print(f"{G}  ──────────────────────────────────────────────────────────{RESET}")

    for f in (
        HTTP_CAPTURE_FILE,
        TCP_CAPTURE_FILE,
        UDP_CAPTURE_FILE,
        UDP_DECODED_FILE,
        UDP_KEYS_FILE,
        KEYS_FILE
    ):
        print(f"  {W}{os.path.abspath(f)}{RESET}")

    ensure_udp_relay()

    threading.Thread(target=run_http, daemon=True).start()
    threading.Thread(target=run_tcp, daemon=True).start()

    time.sleep(0.4)

    print(f"\n{BOLD}{Y}  NETWORK STATUS{RESET}")
    print(f"{G}  ──────────────────────────────────────────────────────────{RESET}")

    print(f"  {G}HTTP{RESET}   {W}127.0.0.1:{HTTP_PORT}{RESET}")
    print(f"  {G}TCP{RESET}    {W}ONLINE → 127.0.0.1:{TCP_ONLINE_PORT}{RESET}")
    print(f"  {G}TCP{RESET}    {W}CHAT   → 127.0.0.1:{TCP_CHAT_PORT}{RESET}")
    print(f"  {G}UDP{RESET}    {W}MATCH  → 0.0.0.0:{UDP_MATCH_PORT}{RESET}")

    print(f"\n{Y}  Waiting for network activity...{RESET}")
    print(f"{G}  ──────────────────────────────────────────────────────────{RESET}")

    try:
        while True:
            time.sleep(1.0)

    except KeyboardInterrupt:
        pass

    finally:
        _cleanup()

        print(f"\n{BOLD}{Y}  SESSION SUMMARY{RESET}")
        print(f"{G}  ──────────────────────────────────────────────────────────{RESET}")

        print(f"  {W}HTTP Captures   : {len(http_capture)}{RESET}")
        print(f"  {W}TCP Captures    : {len(tcp_capture)}{RESET}")
        print(f"  {W}UDP Raw         : {len(udp_capture)}{RESET}")
        print(f"  {W}UDP Decoded     : {len(udp_decoded)}{RESET}")
        print(f"  {W}UDP Packets     : {UDP_PACKETS_RECEIVED}{RESET}")
        print(f"  {W}UDP Keys        : {len(udp_keys_history)}{RESET}")
        print(f"  {W}Session Keys    : {len(session_keys_history)}{RESET}")

        print(f"{G}  ──────────────────────────────────────────────────────────{RESET}")
        print(f"  {Y}NARUTO MITM SESSION CLOSED{RESET}\n")


if __name__ == "__main__":
    main()