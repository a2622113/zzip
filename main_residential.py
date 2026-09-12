#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点家宽订阅池 — 只输出 residential.txt
====================================================
精简版: 只保留"家宽/移动网络"节点的筛选与导出。
脚本位于仓库根目录, 输出 residential.txt 到根目录。

流程:
  抓取订阅源 → 解析全协议 → 测前凭据去重 → 端口预检
  → sing-box 真实测活 → 出口 IP 分类 → 家宽筛选 → residential.txt
"""

import os
import re
import sys
import json
import time
import uuid
import base64
import socket
import zipfile
import tarfile
import subprocess
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

SOURCE_URLS = [
    "https://wild-cloud-9893.heleimail.workers.dev",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://open.heleimail.workers.dev/",
    "https://www.ermao.net/sub/v2ray/ermao.net",
]

OUTPUT_FILE = "residential.txt"          # 直接输出到当前工作目录 (仓库根)

SINGBOX_VERSION = "v1.14.0"
WORKDIR = os.path.dirname(os.path.abspath(__file__))   # 现在 = 仓库根
BASEDIR = WORKDIR                                       # ★ 脚本已在根目录, 不再往上一级
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")          # 仓库根/runtime
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# --- 测活阈值 ---
PROBE_TIMEOUT          = 12
PROBE_RETRY_TIMEOUT    = 4
PORT_KNOCK_TIMEOUT     = 2.5
IP_ECHO_TIMEOUT        = 6.0
SPEED_TEST_BYTES       = 2_500_000
SPEED_TEST_BUDGET      = 5.0
SPEED_MIN_BYTES_PER_S  = 70_000

IP_ECHO_URLS = [
    "https://api.ip.sb/geoip",
    "https://ipinfo.io/json",
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",
]
LIVENESS_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
SPEED_TEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

MAX_WORKERS_TEST   = 48
MAX_WORKERS_FETCH  = 8

IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报
# ══════════════════════════════════════════════════════════════════

CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    "104.16.0.0/12",
)]

DATACENTER_ASNS = {
    13335, 16509, 14618, 15169, 396982, 8075, 8068, 24940, 16276, 14061,
    31898, 63949, 45102, 132203, 20473, 60068, 55081, 197540, 51167, 8560,
    42708, 201814, 49981, 212238, 46652, 141995, 200019, 136907, 39351, 9009,
    174, 3356, 1299, 2914, 6939, 199524, 206096, 49505, 62240, 49304, 34665,
    209242, 219337, 44477, 200651, 202685, 210644, 205628, 51852, 204544,
    397373, 140224, 54866, 45899, 62610, 60205, 8342, 47692, 62041, 56630, 57502,
}

RESIDENTIAL_ASNS = {
    # 台湾
    3462, 9924, 17709, 4780, 18049, 9269, 3491,
    # 香港
    4760, 476, 4515, 9229, 9266, 10103, 9059, 38861,
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    4766, 3786, 17816, 9357,
    # 韩国
    9318, 17816, 9357, 4766,
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,
    2828, 20001, 3549, 6167, 6162, 5056, 11351, 6128,
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # 荷兰/比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # 澳新
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # 新加坡/马来
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # 巴西/拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # 土耳其/俄罗斯/哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # 意/西
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # 印/越/泰/菲/印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 131293, 9336, 23969, 17816, 24099, 38251,
}

IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup",
]

RESIDENTIAL_NAME_PATTERNS = [
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "cust", "customer", "subscriber", "pool", "dynamic-ip",
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free sas", "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    "kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

COUNTRY_NAMES = {
    "HK": "中国香港", "TW": "中国台湾", "JP": "日本", "SG": "新加坡",
    "US": "美国", "KR": "韩国", "DE": "德国", "GB": "英国", "CA": "加拿大",
    "FR": "法国", "NL": "荷兰", "RU": "俄罗斯", "IN": "印度", "AU": "澳大利亚",
    "IT": "意大利", "ES": "西班牙", "TR": "土耳其", "AE": "阿联酋",
    "BR": "巴西", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
    "PH": "菲律宾", "ID": "印尼", "MX": "墨西哥", "AR": "阿根廷",
    "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁", "ZA": "南非",
    "EG": "埃及", "KE": "肯尼亚", "NG": "尼日利亚", "UA": "乌克兰",
    "PL": "波兰", "SE": "瑞典", "NO": "挪威", "FI": "芬兰", "DK": "丹麦",
    "CH": "瑞士", "AT": "奥地利", "BE": "比利时", "IE": "爱尔兰",
    "PT": "葡萄牙", "GR": "希腊", "CZ": "捷克", "RO": "罗马尼亚",
    "HU": "匈牙利", "IL": "以色列", "SA": "沙特", "QA": "卡塔尔",
    "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦", "PK": "巴基斯坦",
    "BD": "孟加拉", "LK": "斯里兰卡", "NP": "尼泊尔", "MM": "缅甸",
    "KH": "柬埔寨", "LA": "老挝", "NZ": "新西兰", "EE": "爱沙尼亚",
    "LV": "拉脱维亚", "LT": "立陶宛", "BG": "保加利亚", "RS": "塞尔维亚",
    "HR": "克罗地亚", "SK": "斯洛伐克", "SI": "斯洛文尼亚",
    "IS": "冰岛", "LU": "卢森堡", "MT": "马耳他", "CY": "塞浦路斯",
    "GE": "格鲁吉亚", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
    "MD": "摩尔多瓦", "BY": "白俄罗斯", "SC": "塞舌尔", "OTHER": "其他地区",
}

# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="ignore")
    except Exception:
        return ""


DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for attempt in range(retries):
        try:
            with DIRECT_SESSION.get(url, timeout=timeout, stream=True,
                                    headers={"Accept": "*/*"}) as r:
                r.raise_for_status()
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1 << 20):
                        if chunk:
                            f.write(chunk)
            if os.path.getsize(tmp) < 1024:
                raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
            os.replace(tmp, dest)
            return
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                wait = 3 * (attempt + 1)
                print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                time.sleep(wait)
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({url}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            import shutil
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            import shutil
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, "
          f"ASN={os.path.getsize(asn_db)//1024}KB")


# ══════════════════════════════════════════════════════════════════
# 节点 URI 解析
# ══════════════════════════════════════════════════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        }
        if params.get("alpn"):
            tls["alpn"] = params["alpn"].split(",")
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    return tls or None


def _parse_transport(params: dict) -> dict:
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None
    outbound = {"type": "vless", "tag": "node", "server": host,
                "server_port": int(port), "uuid": user}
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {"type": "vmess", "tag": "node", "server": server,
                "server_port": port, "uuid": str(data.get("id", "")).strip(),
                "security": "auto"}
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net == "ws":
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan", "tag": "node", "server": host, "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def _ss_outbound(host, port, method, password):
    return {"type": "shadowsocks", "tag": "node", "server": host,
            "server_port": int(port), "method": method.strip().lower(),
            "password": password}


def parse_ss(uri: str):
    body = uri[5:].split("#", 1)[0]
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method),
                                urllib.parse.unquote(password))
    return None


def parse_hysteria2(uri: str):
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2", "tag": "node", "server": host, "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true")
                        or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)
    return outbound


def parse_tuic(uri: str):
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    return {
        "type": "tuic", "tag": "node", "server": host, "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }


def parse_anytls(uri: str):
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls", "tag": "node", "server": host, "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true")
                        or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
}

BLACKLIST_NAME_HINTS = re.compile(
    r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)


def parse_node_uri(uri: str):
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    probe = text.strip()
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, probe):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


def fetch_raw_nodes() -> list:
    nodes = set()
    print("[*] 抓取全部订阅源 ...")

    def _fetch(url):
        last_err = None
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    return url, extract_nodes_from_text(r.text), None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:70]
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, u) for u in SOURCE_URLS]
        for f in as_completed(futs):
            url, got, err = f.result()
            if err:
                print(f"[!] 拉取失败 {url} → {err}")
            else:
                print(f"[+] {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    return list(nodes)


# ══════════════════════════════════════════════════════════════════
# 端口预检
# ══════════════════════════════════════════════════════════════════

_DNS_CACHE = {}


def resolve_host(host: str) -> str:
    if not host or is_ip_literal(host):
        return host or ""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            for a in (r.json().get("Answer") or []):
                if a.get("type") == 1 and a.get("data"):
                    _DNS_CACHE[host] = a["data"]
                    return a["data"]
    except Exception:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    if protocol_type in ("hysteria2", "tuic"):
        return True
    try:
        ip = resolve_host(server)
        if not ip:
            return False
        with socket.create_connection((ip, port), timeout=PORT_KNOCK_TIMEOUT):
            return True
    except Exception:
        return False


def prefilter_candidates(candidates: list) -> list:
    print(f"[*] 端口预检 (TCP {PORT_KNOCK_TIMEOUT}s): {len(candidates)} 候选 ...")
    passed, deferred = [], []

    def _knock(item):
        _, _, server, port, proto = item
        return knock_port(server, port, proto)

    with ThreadPoolExecutor(max_workers=64) as ex:
        for item, ok in zip(candidates, ex.map(_knock, candidates)):
            (passed if ok else deferred).append(item)
    print(f"[+] 预检通过: {len(passed)} | 预检未过(保留低优先级待全测): {len(deferred)}")
    return passed + deferred


# ══════════════════════════════════════════════════════════════════
# sing-box 真实测活
# ══════════════════════════════════════════════════════════════════

def _alloc_socks_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def build_test_config(outbound: dict, socks_port: int) -> dict:
    node = dict(outbound)
    node["tag"] = "node"
    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    front = os.environ.get("FRONT_PROXY", "").strip()
    if front:
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {"type": ftype, "tag": "front-proxy",
                         "server": fhost, "server_port": int(fport)}
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "socks-in",
                      "listen": "127.0.0.1", "listen_port": socks_port, "sniff": False}],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }


def test_single_node(item):
    raw, outbound, server, port, proto = item
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")
    config = build_test_config(outbound, socks_port)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path],
                             capture_output=True, text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            return None
    except Exception:
        pass

    proc = None
    try:
        proc = subprocess.Popen(
            [exe, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        if not ready:
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # 活性
        alive_hits, latency_ms = 0, 99999
        t0 = time.time()
        for i, url in enumerate(LIVENESS_URLS):
            timeout = PROBE_TIMEOUT if i == 0 else PROBE_RETRY_TIMEOUT
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code in (204, 200):
                    alive_hits += 1
                    latency_ms = min(latency_ms, (time.time() - t0) * 1000)
                    break
            except Exception:
                continue
        if alive_hits == 0:
            return None

        # 出口 IP
        exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = None, None, None, None, None
        for url in IP_ECHO_URLS:
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                if r.status_code != 200:
                    continue
                j = r.json()
                ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://api.ip.sb"):
                    exit_country = j.get("country_code")
                    exit_asn = j.get("asn")
                    exit_asn_org = (j.get("asn_organization") or j.get("organization") or "")
                    exit_isp = (j.get("isp") or j.get("organization") or "")
                elif url.startswith("https://ipinfo.io"):
                    exit_country = exit_country or (j.get("country") or "").upper()
                    org = j.get("org") or ""
                    if org and not exit_asn:
                        mm = re.match(r"^AS(\d+)\s+(.*)", org)
                        if mm:
                            exit_asn, exit_asn_org = int(mm.group(1)), mm.group(2)
                    exit_isp = exit_isp or org
                elif "ip-api.com" in url:
                    exit_country = exit_country or (j.get("countryCode") or "").upper()
                    exit_asn = exit_asn or j.get("as")
                    exit_asn_org = exit_asn_org or j.get("asname") or j.get("org") or ""
                    exit_isp = exit_isp or j.get("isp") or j.get("org") or ""
                break
            except Exception:
                continue

        # MITM
        mitm_risk = False
        try:
            r = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                  timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code not in (204, 200):
                mitm_risk = r.status_code in (301, 302, 403, 407, 502, 503) or len(r.content) > 0
        except requests.exceptions.SSLError:
            mitm_risk = True
        except Exception:
            pass

        # 断流
        speed_bps = 0
        for speed_url in SPEED_TEST_URLS:
            downloaded = 0
            t_speed = time.time()
            last_chunk_time = time.time()
            try:
                with PROBE_SESSION.get(speed_url, proxies=proxies,
                                       timeout=(5, SPEED_TEST_BUDGET), stream=True) as r:
                    if r.status_code == 200:
                        for chunk in r.iter_content(chunk_size=65536):
                            now = time.time()
                            if chunk:
                                downloaded += len(chunk)
                                last_chunk_time = now
                            if now - t_speed > SPEED_TEST_BUDGET:
                                break
                            if now - last_chunk_time > 3.0:
                                break
                elapsed = max(time.time() - t_speed, 0.001)
                if downloaded > 0:
                    speed_bps = int(downloaded / elapsed)
                    break
            except Exception:
                continue

        is_stalled = speed_bps < SPEED_MIN_BYTES_PER_S

        return {
            "raw": raw, "server": server, "port": port, "proto": proto,
            "alive": True, "latency_ms": int(latency_ms),
            "exit_ip": exit_ip,
            "exit_country_online": exit_country,
            "exit_asn_online": exit_asn,
            "exit_asn_org_online": (exit_asn_org or "")[:120],
            "exit_isp_online": (exit_isp or "")[:120],
            "mitm_risk": mitm_risk,
            "speed_bps": speed_bps,
            "is_stalled": is_stalled,
        }
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    done_count = [0]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(test_single_node, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r = fut.result()
            if r:
                results.append(r)
            if done_count[0] % 40 == 0:
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, 通过 {len(results)}")

    alive = [r for r in results if r["alive"] and not r["is_stalled"]]
    mitm = sum(1 for r in results if r["mitm_risk"])
    stalled = sum(1 for r in results if r["is_stalled"])
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流淘汰 {stalled} | MITM 风险 {mitm}")
    return results


# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 + 分类
# ══════════════════════════════════════════════════════════════════

def ip_api_batch_lookup(ip_list: list) -> dict:
    info = {}
    session = requests.Session()
    session.trust_env = True
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "cdn", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = mobile_flag = proxy_flag = False

    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        org_lower = (ip_api_rec.get("asname") or ip_api_rec.get("org") or org_lower).lower()

    if hosting_flag:
        return "datacenter", 90
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    rdns = get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    return "unknown", 30


# ══════════════════════════════════════════════════════════════════
# 节点 → v2ray URI
# ══════════════════════════════════════════════════════════════════

def outbound_to_v2ray_link(node: dict, name: str) -> str:
    t = node.get("type")
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype, "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()

    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"

    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return (f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}"
                f"?{query}#{urllib.parse.quote(name)}")

    if t == "shadowsocks":
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"

    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return (f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}"
                f"?{query}#{urllib.parse.quote(name)}")

    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return (f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}"
                f"@{server}:{port}?{query}#{urllib.parse.quote(name)}")

    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return (f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}"
                f"?{query}#{urllib.parse.quote(name)}")

    return ""


# ══════════════════════════════════════════════════════════════════
# 家宽筛选 + 导出
# ══════════════════════════════════════════════════════════════════

def make_node_name(item, idx):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    tag = " (家宽)" if item["net_type"] == "residential" else " (移动家宽)"
    return f"{flag} {cname} {idx:02d}{tag} - xiaohe"


def filter_residential(test_results: list):
    """从测活结果中筛选家宽/移动节点, 出口IP唯一化, 只保留 residential/mobile & conf>=60"""
    print("[*] 出口 IP 情报与家宽筛选 ...")

    all_exit_ips = []
    seen_ip = set()
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个")

    ip_api_info = {}
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    nodes = []
    for r in test_results:
        exit_ip = r["exit_ip"]
        country = r.get("exit_country_online")
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        if country_reader and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        if (not country or country in ("OTHER", "ZZ")) and r.get("server"):
            srv_ip = r["server"] if is_ip_literal(r["server"]) else resolve_host(r["server"])
            if srv_ip and country_reader:
                off_c, srv_asn, srv_org = offline_ip_lookup(srv_ip, country_reader, asn_reader)
                if off_c and off_c not in ("OTHER", "ZZ"):
                    country = off_c
                    asn, org = asn or srv_asn, org or srv_org

        rec = ip_api_info.get(exit_ip, {})
        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"], "server": r["server"], "port": r["port"], "proto": r["proto"],
            "country": (country or "OTHER").upper(),
            "net_type": net_type, "confidence": confidence,
            "exit_ip": exit_ip, "asn": asn, "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "latency_ms": r["latency_ms"],
            "speed_bps": r["speed_bps"],
            "mitm_risk": r["mitm_risk"],
            "is_stalled": r["is_stalled"],
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # 过滤 MITM / 断流
    safe_nodes = [n for n in nodes if not n["mitm_risk"]]
    mitm_dropped = len(nodes) - len(safe_nodes)
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    print(f"[*] MITM 劫持高风险节点已剔除: {mitm_dropped}")

    # 全量去重 (出口IP+端口)
    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or n["latency_ms"] < cur["latency_ms"]:
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)}")

    # 家宽筛选: residential/mobile + conf>=60, 出口IP唯一化 (防同IP刷屏)
    residential = []
    res_seen_ip = set()
    for n in unique_nodes:
        if n["net_type"] in ("residential", "mobile") and n["confidence"] >= 60:
            if n["exit_ip"] and n["exit_ip"] not in res_seen_ip:
                res_seen_ip.add(n["exit_ip"])
                residential.append(n)

    residential.sort(key=lambda x: x["latency_ms"])
    print(f"[*] 家宽/移动节点: {len(residential)}")
    return residential


def export_residential(residential: list):
    links = []
    for idx, item in enumerate(residential, start=1):
        name = make_node_name(item, idx)
        parsed = parse_node_uri(item["raw"])
        if not parsed:
            continue
        ob = parsed[0]
        ob.pop("detour", None)
        link = outbound_to_v2ray_link(ob, name)
        if link:
            links.append(link)

    if not links:
        print("[!] 无有效家宽链接 — 保留上次 output")
        return 0

    encoded = base64.b64encode("\n".join(links).encode()).decode()
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(encoded)
    print(f"[+] 已写出 {OUTPUT_FILE} ({len(links)} 个家宽节点)")
    return len(links)


# ══════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════

def main():
    t_start = time.time()
    print(f"==== 家宽节点订阅池 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    setup_environment()

    raw_nodes = fetch_raw_nodes()

    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(
                uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 测前凭据去重
    def cred_fingerprint(outbound, proto):
        try:
            if proto == "vless":
                return f"{outbound.get('uuid','')}"
            if proto == "vmess":
                return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
            if proto == "trojan":
                return f"{outbound.get('password','')}"
            if proto == "shadowsocks":
                return f"{outbound.get('method','')}|{outbound.get('password','')}"
            if proto == "hysteria2":
                return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
            if proto == "tuic":
                return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
            if proto == "anytls":
                return f"{outbound.get('password','')}"
            return json.dumps({k: v for k, v in outbound.items()
                              if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
        except Exception:
            return ""

    dedup_map = {}
    deduped = []
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key not in dedup_map:
            dedup_map[key] = []
            deduped.append(item)
        dedup_map[key].append(uri)
    dup_count = sum(len(v) - 1 for v in dedup_map.values())
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} (剔除重复 {dup_count})")
    candidates = deduped

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    if not candidates:
        print("[!] 无可测节点 — 保留上次 output")
        return

    candidates = prefilter_candidates(candidates)
    test_results = run_liveness_test(candidates)

    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output")
        return

    residential = filter_residential(test_results)
    if not residential:
        print("[!] 未筛选出家宽节点 — 保留上次 output")
        return

    count = export_residential(residential)

    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s | 抓取 {len(raw_nodes)} → 解析 {len(candidates)} "
          f"→ 真活 {len(test_results)} → 家宽 {count}")
    by_cc = {}
    for n in residential:
        by_cc[n["country"]] = by_cc.get(n["country"], 0) + 1
    print(f"家宽国家分布: {sorted(by_cc.items(), key=lambda x: -x[1])[:10]}")


if __name__ == "__main__":
    main()