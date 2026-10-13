"""
Клієнтський сервіс інформування споживачів Вінницької області про планові ремонти та аварії.

Запуск:  pip install streamlit requests
         streamlit run app.py

Безпека обміну з центром моніторингу:
  * лише HTTPS, перевірка TLS-сертифіката, Bearer-токен, таймаути;
  * підпис відповіді HMAC-SHA256 (X-Signature над "<X-Timestamp>.<тіло>");
  * захист від повторного програвання (вікно 5 хв за X-Timestamp);
  * сувора валідація полів; секрети беруться з .streamlit/secrets.toml.

Без налаштувань працює ДЕМО-режим із вбудованим симулятором центру
(дані також підписуються й перевіряються).

.streamlit/secrets.toml (приклад):
  MONITORING_URL = "https://monitoring.example.com/api/v1/incidents"
  MONITORING_TOKEN = "..."
  MONITORING_HMAC_SECRET = "..."
  ADMIN_PASSWORD = "..."
  POLL_INTERVAL_SEC = 60
  SMTP_HOST = "smtp.example.com"; SMTP_PORT = 587
  SMTP_USER = "..."; SMTP_PASSWORD = "..."; SMTP_FROM = "noreply@example.com"
  TELEGRAM_BOT_TOKEN = "..."
"""
import hashlib
import hmac
import json
import functools
import html as _html
import math
import os
import random
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import pandas as pd
import pydeck as pdk
import streamlit as st

try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
except ImportError:  # графіки надійності потребують plotly
    px = go = make_subplots = None

try:
    import requests
except ImportError:  # потрібен лише для бойового режиму та Telegram
    requests = None

DB_PATH = os.environ.get("NOTIFY_DB", "notify.db")
DB_LOCK = threading.RLock()
MAX_SKEW_SEC = 300
KINDS = {"outage": "🚨 Аварія", "planned": "🛠️ Плановий ремонт"}
STATUSES = {"active": "Триває", "scheduled": "Заплановано", "resolved": "Усунено"}
REPORT_STATUS = {"new": "Нове", "in_progress": "В роботі", "closed": "Закрито"}
REPORT_CATEGORIES = ["Немає електропостачання", "Низька/нестабільна напруга", "Пошкодження обладнання", "Інше"]
DEMO_SECRET = "demo-secret-change-me"
ADMIN_PASSWORD = "Vinnytsia2026"  # пароль диспетчера за замовчуванням (можна перевизначити через secrets)

# Населені пункти Вінницької області (код лінії: назва, район, широта, довгота).
# Координати та належність до районів (після реформи 2020 р.) орієнтовні — уточніть за потреби.
SETTLEMENTS = {
    "VIN": ("Вінниця", "Вінницький", 49.2331, 28.4682),
    "KAL": ("Калинівка", "Вінницький", 49.4560, 28.5120),
    "TYV": ("Тиврів", "Вінницький", 49.0150, 28.4920),
    "ILL": ("Іллінці", "Вінницький", 49.1030, 29.2150),
    "LYP": ("Липовець", "Вінницький", 49.2150, 29.0130),
    "NEM": ("Немирів", "Вінницький", 48.9700, 28.8400),
    "POH": ("Погребище", "Вінницький", 49.4850, 29.2670),
    "ZHM": ("Жмеринка", "Жмеринський", 49.0354, 28.1147),
    "SHA": ("Шаргород", "Жмеринський", 48.7380, 28.0850),
    "BAR": ("Бар", "Жмеринський", 49.0750, 27.6770),
    "MKU": ("Муровані Курилівці", "Жмеринський", 48.7230, 27.5110),
    "MOG": ("Могилів-Подільський", "Могилів-Подільський", 48.4498, 27.7978),
    "YAM": ("Ямпіль", "Могилів-Подільський", 48.2310, 28.2820),
    "KHM": ("Хмільник", "Хмільницький", 49.5560, 27.9710),
    "KOZ": ("Козятин", "Хмільницький", 49.7130, 28.8450),
    "TUL": ("Тульчин", "Тульчинський", 48.6783, 28.8486),
    "TOM": ("Томашпіль", "Тульчинський", 48.5480, 28.5130),
    "KRY": ("Крижопіль", "Тульчинський", 48.3800, 28.8650),
    "HAI": ("Гайсин", "Гайсинський", 48.8097, 29.3844),
    "BER": ("Бершадь", "Гайсинський", 48.3703, 29.5214),
    "LAD": ("Ладижин", "Гайсинський", 48.6836, 29.2330),
}
LINES = {f"{code}-{n}": code for code in SETTLEMENTS for n in (1, 2, 3)}  # фідери: VIN-1, VIN-2 ...

PROJECT_LINKS = [
    ("Grid What-If", "https://grid-whatif.streamlit.app/"),
    ("MVP Blob", "https://mvp-blob.streamlit.app/?theme=light"),
    ("GIS Dispatch", "https://gis-dispatch.streamlit.app/"),
]


# ───────────────────────── Топологія мережі (Power Grid Graph) ─────────────────────────
# Підстанція 110/35 кВ → Фідер 10 кВ → ТП 10/0.4 кВ → Споживач.
# Схема демонстраційна (синтетична): замініть SUBSTATIONS/логіку build_grid на дані вашого ГІС/SCADA.
SUBSTATIONS = {  # id підстанції: (пункт розташування, коди пунктів, що отримують від неї живлення)
    "PS-VIN": ("VIN", ["VIN", "TYV", "KAL"]),
    "PS-ZHM": ("ZHM", ["ZHM", "BAR", "SHA", "MKU"]),
    "PS-MOG": ("MOG", ["MOG", "YAM"]),
    "PS-KHM": ("KHM", ["KHM", "KOZ", "POH"]),
    "PS-TUL": ("TUL", ["TUL", "TOM", "KRY", "NEM"]),
    "PS-HAI": ("HAI", ["HAI", "LAD", "BER"]),
    "PS-LYP": ("LYP", ["LYP", "ILL"]),
}
NODE_TYPES = {"sub": "Підстанція 110/35 кВ", "feeder": "Фідер 10 кВ", "tp": "ТП 10/0.4 кВ"}
LEVELS = {0: "🟢 Норма", 2: "🟠 Планові роботи", 3: "🔴 Аварія"}
COLORS = {0: [46, 160, 67, 235], 2: [251, 140, 0, 235], 3: [229, 57, 53, 235]}
GRID: dict = {}  # id вузла -> {id, type, name, parent, lat, lon}


def build_grid():
    for sid, (host, _codes) in SUBSTATIONS.items():
        name, _r, lat, lon = SETTLEMENTS[host]
        GRID[sid] = dict(id=sid, type="sub", name=f"ПС 110/35 кВ «{name}»", parent=None,
                         lat=lat + 0.012, lon=lon - 0.016)
    for sid, (_host, codes) in SUBSTATIONS.items():
        for code in codes:
            name, _r, lat, lon = SETTLEMENTS[code]
            for n in (1, 2, 3):
                lid, ang = f"{code}-{n}", math.radians(120 * n)
                GRID[lid] = dict(id=lid, type="feeder", name=f"Фідер 10 кВ {lid} ({name})", parent=sid,
                                 lat=lat + 0.02 * math.sin(ang), lon=lon + 0.03 * math.cos(ang))
                for k, da in ((1, 25), (2, -25)):
                    a2, tid = ang + math.radians(da), f"TP-{lid}-{k}"
                    GRID[tid] = dict(id=tid, type="tp", name=f"ТП 10/0.4 кВ {lid}-{k}", parent=lid,
                                     lat=lat + 0.035 * math.sin(a2), lon=lon + 0.052 * math.cos(a2),
                                     # кількість абонентів на ТП — модель (120–400); замініть даними білінгу
                                     customers=120 + int(hashlib.md5(tid.encode()).hexdigest()[:6], 16) % 281)


build_grid()


def ancestors(node: str) -> list[str]:
    """Вузол і всі вищі вузли: [ТП, фідер, підстанція]."""
    out = []
    while node in GRID:
        out.append(node)
        node = GRID[node]["parent"]
    return out


def descendants(node: str) -> list[str]:
    """Вузол і всі підпорядковані вузли (у порядку «батьки перед дітьми»)."""
    return [i for i in GRID if node in ancestors(i)]


def tp_of(account, line: str) -> str:
    """ТП споживача (детерміновано від № рахунку, 2 ТП на фідер)."""
    return f"TP-{line}-{int(hashlib.md5(str(account).encode()).hexdigest(), 16) % 2 + 1}"


def chain_ids(c) -> list[str]:
    return ancestors(tp_of(c["account"], c["line_id"])) if c["line_id"] in GRID else [c["line_id"]]


def node_code(node: str):
    n = GRID.get(node)
    if not n:
        return None
    return SUBSTATIONS[node][0] if n["type"] == "sub" else (node.split("-")[1] if n["type"] == "tp" else node.split("-")[0])


def consumers_under(node: str):
    """Усі споживачі, підпорядковані вузлу (каскад). Для невідомого вузла — за line_id."""
    n = GRID.get(node)
    if not n:
        return q("SELECT * FROM consumers WHERE line_id=?", (node,))
    lines = [n["parent"]] if n["type"] == "tp" else [i for i in descendants(node) if GRID[i]["type"] == "feeder"]
    rows = q(f"SELECT * FROM consumers WHERE line_id IN ({','.join('?' * len(lines))})", tuple(lines))
    return [r for r in rows if n["type"] != "tp" or tp_of(r["account"], r["line_id"]) == node]


def line_label(line: str) -> str:
    n = GRID.get(line)
    if n and n["type"] != "feeder":
        return n["name"]
    code = LINES.get(line)
    return f"{line} · {SETTLEMENTS[code][0]}" if code else line


# ───────────────────────────── Конфігурація ─────────────────────────────
def load_config() -> dict:
    def g(key, default=None):
        try:
            return st.secrets.get(key, os.environ.get(key, default))
        except Exception:
            return os.environ.get(key, default)

    cfg = {k: g(k) for k in (
        "MONITORING_URL", "MONITORING_TOKEN", "MONITORING_HMAC_SECRET", "ADMIN_PASSWORD",
        "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "TELEGRAM_BOT_TOKEN")}
    cfg["POLL_INTERVAL_SEC"] = int(g("POLL_INTERVAL_SEC", 20))
    cfg["DEMO"] = not (cfg["MONITORING_URL"] and cfg["MONITORING_HMAC_SECRET"])
    if cfg["DEMO"]:
        cfg["MONITORING_HMAC_SECRET"] = DEMO_SECRET
    cfg["ADMIN_PASSWORD"] = cfg["ADMIN_PASSWORD"] or ADMIN_PASSWORD
    return cfg


# ───────────────────────────── База даних ─────────────────────────────
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with DB_LOCK, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS consumers(
            id INTEGER PRIMARY KEY, account TEXT UNIQUE, name TEXT, address TEXT, line_id TEXT,
            salt TEXT, pin_hash TEXT, email TEXT, phone TEXT, telegram_chat TEXT,
            ch_email INT DEFAULT 1, ch_sms INT DEFAULT 1, ch_tg INT DEFAULT 0);
        CREATE TABLE IF NOT EXISTS incidents(
            id TEXT PRIMARY KEY, line_id TEXT, kind TEXT, title TEXT, description TEXT,
            starts_at TEXT, ends_at TEXT, status TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS notif_log(
            id INTEGER PRIMARY KEY, ts TEXT, incident_id TEXT, consumer_id INT, channel TEXT,
            event_key TEXT, status TEXT, detail TEXT,
            UNIQUE(incident_id, consumer_id, channel, event_key));
        CREATE TABLE IF NOT EXISTS reports(
            id INTEGER PRIMARY KEY, ts TEXT, consumer_id INT, line_id TEXT, category TEXT,
            text TEXT, status TEXT DEFAULT 'new');
        CREATE TABLE IF NOT EXISTS interruptions(
            id INTEGER PRIMARY KEY, incident_id TEXT, node_id TEXT, kind TEXT, start_ts TEXT,
            end_ts TEXT, cause TEXT, synthetic INT DEFAULT 0);
        CREATE TABLE IF NOT EXISTS poll_log(
            id INTEGER PRIMARY KEY, ts TEXT, ok INT, message TEXT);
        """)


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000).hex()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fmt_dt(s) -> str:
    try:
        return datetime.fromisoformat(s).astimezone().strftime("%d.%m.%Y %H:%M")
    except Exception:
        return "—"


# ───────────────────── Симулятор центру моніторингу (демо) ─────────────────────
class Simulator:
    def __init__(self):
        self.incidents: dict[str, dict] = {}
        self.lock = threading.Lock()
        now = datetime.now(timezone.utc)
        self.add("planned", "VIN-2", "Заміна опор на вул. Соборній (м. Вінниця)",
                 "Планове відключення для заміни опор ЛЕП.",
                 now + timedelta(hours=20), now + timedelta(hours=26), "scheduled")

    def add(self, kind, line, title, desc, start, end, status):
        with self.lock:
            iid = f"INC-{len(self.incidents) + 1:04d}"
            self.incidents[iid] = dict(
                id=iid, line_id=line, kind=kind, title=title, description=desc,
                starts_at=start.replace(microsecond=0).isoformat(),
                ends_at=end.replace(microsecond=0).isoformat() if end else None,
                status=status, updated_at=now_iso())

    def start(self, iid):
        with self.lock:
            inc = self.incidents.get(iid)
            if inc and inc["status"] == "scheduled":
                inc.update(status="active", starts_at=now_iso(), updated_at=now_iso())

    def resolve(self, iid):
        with self.lock:
            if iid in self.incidents:
                self.incidents[iid].update(status="resolved", updated_at=now_iso())

    def response(self, secret: str):
        with self.lock:
            body = json.dumps({"incidents": list(self.incidents.values())}).encode()
        ts = str(int(time.time()))
        return body, ts, sign(secret, ts, body)


@st.cache_resource
def get_simulator() -> Simulator:
    return Simulator()


# ───────────────────── Безпечне отримання даних ─────────────────────
def sign(secret: str, ts: str, body: bytes) -> str:
    return hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify(secret: str, ts: str, signature: str, body: bytes):
    try:
        skew = abs(time.time() - int(ts))
    except (TypeError, ValueError):
        raise ValueError("Некоректний X-Timestamp")
    if skew > MAX_SKEW_SEC:
        raise ValueError("Часова мітка застаріла (можливий replay-атак)")
    if not hmac.compare_digest(sign(secret, ts, body), signature or ""):
        raise ValueError("Невірний підпис відповіді центру моніторингу")


def validate_incident(i: dict) -> dict:
    need = ("id", "line_id", "kind", "title", "status", "updated_at")
    if any(not isinstance(i.get(k), str) or not i[k] for k in need):
        raise ValueError(f"Неповний запис інциденту: {str(i)[:80]}")
    if i["kind"] not in KINDS or i["status"] not in STATUSES:
        raise ValueError(f"Невідомий тип/статус: {i['kind']}/{i['status']}")
    return {k: (str(i.get(k))[:500] if i.get(k) else None) for k in (
        "id", "line_id", "kind", "title", "description", "starts_at", "ends_at", "status", "updated_at")}


def fetch_incidents(cfg: dict) -> list[dict]:
    if cfg["DEMO"]:
        body, ts, sig = get_simulator().response(cfg["MONITORING_HMAC_SECRET"])
    else:
        if requests is None:
            raise RuntimeError("Встановіть пакет requests")
        if not cfg["MONITORING_URL"].startswith("https://"):
            raise ValueError("Дозволено лише HTTPS-з'єднання")
        r = requests.get(cfg["MONITORING_URL"], timeout=10, verify=True,
                         headers={"Authorization": f"Bearer {cfg['MONITORING_TOKEN']}",
                                  "Accept": "application/json"})
        r.raise_for_status()
        body, ts, sig = r.content, r.headers.get("X-Timestamp"), r.headers.get("X-Signature")
    verify(cfg["MONITORING_HMAC_SECRET"], ts, sig, body)
    return [validate_incident(i) for i in json.loads(body)["incidents"]]


# ───────────────────── Сповіщення ─────────────────────
def build_message(inc: sqlite3.Row | dict, c: sqlite3.Row) -> tuple[str, str]:
    kind, status = KINDS[inc["kind"]], STATUSES[inc["status"]]
    subj = f"{kind}: {inc['title']} ({status})"
    body = (f"Шановний(а) {c['name']}!\n\n{kind} на ділянці мережі {line_label(inc['line_id'])} "
            f"(адреса: {c['address']}).\nСтатус: {status}\n"
            f"Початок: {fmt_dt(inc['starts_at'])}\nОрієнтовне завершення: {fmt_dt(inc['ends_at'])}\n"
            f"{inc['description'] or ''}\n\nОстаннє оновлення: {fmt_dt(inc['updated_at'])}")
    return subj, body


def send_email(cfg, to, subj, body) -> str:
    if not (cfg["SMTP_HOST"] and to):
        return "імітація (SMTP не налаштовано)"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg["SMTP_FROM"] or cfg["SMTP_USER"], to, subj
    msg.set_content(body)
    with smtplib.SMTP(cfg["SMTP_HOST"], int(cfg["SMTP_PORT"] or 587), timeout=10) as s:
        s.starttls()
        if cfg["SMTP_USER"]:
            s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
        s.send_message(msg)
    return "надіслано"


def send_telegram(cfg, chat, subj, body) -> str:
    if not (cfg["TELEGRAM_BOT_TOKEN"] and chat and requests):
        return "імітація (Telegram не налаштовано)"
    r = requests.post(f"https://api.telegram.org/bot{cfg['TELEGRAM_BOT_TOKEN']}/sendMessage",
                      json={"chat_id": chat, "text": f"{subj}\n\n{body}"}, timeout=10)
    r.raise_for_status()
    return "надіслано"


def notify_for(cfg, inc: dict):
    """Сповістити всіх споживачів лінії; дедуплікація через UNIQUE у notif_log."""
    event_key = f"{inc['status']}:{inc['updated_at']}"
    consumers = consumers_under(inc["line_id"])  # каскад: усі споживачі нижче вузла аварії
    with DB_LOCK, db() as con:
        for c in consumers:
            subj, body = build_message(inc, c)
            channels = [("email", c["ch_email"], lambda: send_email(cfg, c["email"], subj, body)),
                        ("sms", c["ch_sms"], lambda: f"імітація SMS на {c['phone']}: {subj}"),
                        ("telegram", c["ch_tg"], lambda: send_telegram(cfg, c["telegram_chat"], subj, body))]
            for name, enabled, fn in channels:
                if not enabled:
                    continue
                try:
                    con.execute("INSERT INTO notif_log(ts,incident_id,consumer_id,channel,event_key,status,detail)"
                                " VALUES(?,?,?,?,?,?,?)",
                                (now_iso(), inc["id"], c["id"], name, event_key, "pending", ""))
                except sqlite3.IntegrityError:
                    continue  # уже надсилали
                try:
                    status, detail = "ok", fn()
                except Exception as e:  # помилка каналу не зупиняє решту
                    status, detail = "error", str(e)[:200]
                con.execute("UPDATE notif_log SET status=?, detail=? WHERE incident_id=? AND consumer_id=? "
                            "AND channel=? AND event_key=?",
                            (status, detail, inc["id"], c["id"], name, event_key))


def poll_once(cfg) -> str:
    try:
        incidents = fetch_incidents(cfg)
        changed = 0
        with DB_LOCK:
            for inc in incidents:
                with db() as con:
                    old = con.execute("SELECT updated_at FROM incidents WHERE id=?", (inc["id"],)).fetchone()
                    if old and old["updated_at"] == inc["updated_at"]:
                        continue
                    con.execute("INSERT OR REPLACE INTO incidents VALUES(:id,:line_id,:kind,:title,:description,"
                                ":starts_at,:ends_at,:status,:updated_at)", inc)
                changed += 1
                track_interruption(inc)
                notify_for(cfg, inc)
        msg, ok = f"Отримано {len(incidents)}, змінено {changed}", 1
    except Exception as e:
        msg, ok = f"Помилка: {e}", 0
    with DB_LOCK, db() as con:
        con.execute("INSERT INTO poll_log(ts,ok,message) VALUES(?,?,?)", (now_iso(), ok, msg))
        con.execute("DELETE FROM poll_log WHERE id NOT IN (SELECT id FROM poll_log ORDER BY id DESC LIMIT 200)")
    return msg


@st.cache_resource
def start_poller(cfg_items: tuple):
    cfg = dict(cfg_items)

    def loop():
        while True:
            poll_once(cfg)
            time.sleep(max(5, cfg["POLL_INTERVAL_SEC"]))

    t = threading.Thread(target=loop, daemon=True, name="poller")
    t.start()
    return t


# ───────────────────── Інтерфейс ─────────────────────
def incident_cards(rows):
    if not rows:
        st.success("✅ Активних подій на вашій лінії немає.")
    for r in rows:
        box = st.error if r["kind"] == "outage" and r["status"] == "active" else (
            st.success if r["status"] == "resolved" else st.warning)
        box(f"**{KINDS[r['kind']]} — {r['title']}**  \n"
            f"Статус: **{STATUSES[r['status']]}** · Початок: {fmt_dt(r['starts_at'])} · "
            f"Завершення: {fmt_dt(r['ends_at'])}  \n{r['description'] or ''}  \n"
            f"📍 {line_label(r['line_id'])} · _Оновлено: {fmt_dt(r['updated_at'])}_")


def q(sql, params=()):
    with DB_LOCK, db() as con:
        return con.execute(sql, params).fetchall()


def qdf(sql, params=()) -> pd.DataFrame:
    with DB_LOCK, db() as con:
        return pd.read_sql(sql, con, params=params)


def until(s) -> str:
    try:
        sec = int((datetime.fromisoformat(s) - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        return "—"
    if sec <= 0:
        return "розпочато"
    days, rem = divmod(sec, 86400)
    return f"{days} д {rem // 3600} г" if days else f"{rem // 3600} г {rem % 3600 // 60} хв"


def span(a, b) -> str:
    try:
        sec = max(int((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()), 0)
    except Exception:
        return "—"
    return f"{sec // 3600} г {sec % 3600 // 60} хв"


def test_channels(cfg, c) -> list[str]:
    subj, body = "🔔 Тестове сповіщення", f"Це перевірка каналів зв'язку для {c['name']} ({c['address']})."
    out = []
    for name, on, fn in (("Email", c["ch_email"], lambda: send_email(cfg, c["email"], subj, body)),
                         ("SMS", c["ch_sms"], lambda: f"імітація SMS на {c['phone'] or '—'}"),
                         ("Telegram", c["ch_tg"], lambda: send_telegram(cfg, c["telegram_chat"], subj, body))):
        if not on:
            continue
        try:
            out.append(f"✅ {name}: {fn()}")
        except Exception as e:
            out.append(f"❌ {name}: {str(e)[:120]}")
    return out or ["Жоден канал не увімкнено."]


def consumer_portal():
    cfg = load_config()
    st.subheader("Кабінет споживача")
    if "consumer_id" not in st.session_state:
        with st.form("login"):
            acc = st.text_input("Номер особового рахунку")
            pin = st.text_input("PIN-код", type="password")
            if st.form_submit_button("Увійти"):
                rows = q("SELECT * FROM consumers WHERE account=?", (acc.strip(),))
                c = rows[0] if rows else None
                if c and hmac.compare_digest(hash_pin(pin, c["salt"]), c["pin_hash"]):
                    st.session_state.consumer_id = c["id"]
                    st.rerun()
                time.sleep(1)  # уповільнення підбору PIN
                st.error("Невірний рахунок або PIN")
        st.caption("Демо: рахунок 1001, PIN 1234" if cfg["DEMO"] else "")
        return

    rows = q("SELECT * FROM consumers WHERE id=?", (st.session_state.consumer_id,))
    if not rows:
        del st.session_state["consumer_id"]
        st.rerun()
    c = rows[0]
    code = LINES.get(c["line_id"])
    raion = SETTLEMENTS[code][1] if code else "—"
    chain = chain_ids(c)
    ph = ",".join("?" * len(chain))
    h1, h2 = st.columns([5, 1])
    h1.markdown(f"#### 👤 {c['name']}")
    h1.caption(f"Рахунок {c['account']} · {c['address']} · {raion} район · лінія {line_label(c['line_id'])}")
    if c["line_id"] in GRID:
        h1.caption("🔌 Живлення: " + " ← ".join(GRID[i]["name"] for i in chain) + " · Споживач")
    if h2.button("Вийти"):
        del st.session_state["consumer_id"]
        st.rerun()

    tabs = st.tabs(["🏠 Поточний стан", "📅 Графік робіт", "🗂️ Історія", "🔔 Сповіщення",
                    "📝 Звернення", "⚙️ Профіль"])

    with tabs[0]:
        @st.fragment(run_every=5)
        def live():
            ev = q(f"SELECT * FROM incidents WHERE line_id IN ({ph}) AND status!='resolved' "
                   "ORDER BY (kind='outage') DESC, updated_at DESC", tuple(chain))
            active = [r for r in ev if r["status"] == "active"]
            plan = [r for r in ev if r["status"] == "scheduled"]
            k1, k2, k3 = st.columns(3)
            k1.metric("Стан лінії", "🔴 Аварія" if any(r["kind"] == "outage" for r in active)
                      else "🟠 Ремонт" if active else "🟢 Норма")
            k2.metric("Активні події", len(active))
            k3.metric("Найближчі роботи", until(min(r["starts_at"] for r in plan)) if plan else "—")
            incident_cards(ev)
            st.caption(f"Оновлено {datetime.now().strftime('%H:%M:%S')} · автооновлення кожні 5 с")

        live()

    with tabs[1]:
        plan = q(f"SELECT * FROM incidents WHERE line_id IN ({ph}) AND kind='planned' AND status='scheduled' "
                 "ORDER BY starts_at", tuple(chain))
        st.markdown("**Заплановані роботи на вашій лінії**")
        if plan:
            st.dataframe(pd.DataFrame([{"Робота": r["title"], "Початок": fmt_dt(r["starts_at"]),
                                        "Завершення": fmt_dt(r["ends_at"]),
                                        "Тривалість": span(r["starts_at"], r["ends_at"]),
                                        "Через": until(r["starts_at"])} for r in plan]),
                         use_container_width=True, hide_index=True)
        else:
            st.success("Планових відключень не заплановано.")
        if code:
            others = [l for l in LINES if LINES[l] == code and l != c["line_id"]]
            near = q(f"SELECT * FROM incidents WHERE status!='resolved' AND line_id IN "
                     f"({','.join('?' * len(others))})", others)
            st.markdown(f"**Інші лінії: {SETTLEMENTS[code][0]}**")
            if near:
                st.dataframe(pd.DataFrame([{"Лінія": r["line_id"], "Тип": KINDS[r["kind"]],
                                            "Подія": r["title"], "Статус": STATUSES[r["status"]]}
                                           for r in near]), use_container_width=True, hide_index=True)
            else:
                st.caption("На інших лініях вашого населеного пункту подій немає.")

    with tabs[2]:
        hist = q(f"SELECT * FROM incidents WHERE line_id IN ({ph}) ORDER BY updated_at DESC", tuple(chain))
        m1, m2, m3 = st.columns(3)
        m1.metric("Усього подій", len(hist))
        m2.metric("Аварій", sum(r["kind"] == "outage" for r in hist))
        m3.metric("Планових робіт", sum(r["kind"] == "planned" for r in hist))
        f1, f2 = st.columns(2)
        kinds = f1.multiselect("Тип", list(KINDS), default=list(KINDS), format_func=KINDS.get)
        sts = f2.multiselect("Статус", list(STATUSES), default=list(STATUSES), format_func=STATUSES.get)
        data = [{"Подія": r["title"], "Тип": KINDS[r["kind"]], "Статус": STATUSES[r["status"]],
                 "Початок": fmt_dt(r["starts_at"]), "Завершення": fmt_dt(r["ends_at"]),
                 "Тривалість": span(r["starts_at"], r["updated_at"] if r["status"] == "resolved" else r["ends_at"]),
                 "Оновлено": fmt_dt(r["updated_at"])}
                for r in hist if r["kind"] in kinds and r["status"] in sts]
        if data:
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("⬇️ Завантажити CSV", df.to_csv(index=False).encode("utf-8-sig"),
                               "history.csv", "text/csv")
        else:
            st.info("Подій за обраними фільтрами немає.")

    with tabs[3]:
        df = qdf("SELECT n.ts AS Час, i.title AS Подія, n.channel AS Канал, n.status AS Статус, "
                 "n.detail AS Деталі FROM notif_log n LEFT JOIN incidents i ON i.id=n.incident_id "
                 "WHERE n.consumer_id=? ORDER BY n.id DESC LIMIT 200", (c["id"],))
        if df.empty:
            st.info("Сповіщень поки немає.")
        else:
            chans = st.multiselect("Канал", sorted(df["Канал"].unique()), default=sorted(df["Канал"].unique()))
            st.dataframe(df[df["Канал"].isin(chans)], use_container_width=True, hide_index=True)
        if st.button("📨 Надіслати тестове сповіщення"):
            for line in test_channels(cfg, c):
                st.write(line)

    with tabs[4]:
        with st.form("report", clear_on_submit=True):
            cat = st.selectbox("Тема звернення", REPORT_CATEGORIES)
            txt = st.text_area("Опишіть проблему", max_chars=1000)
            if st.form_submit_button("Надіслати диспетчеру"):
                recent = q("SELECT COUNT(*) AS n FROM reports WHERE consumer_id=? AND ts>?",
                           (c["id"], (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()))[0]["n"]
                if len(txt.strip()) < 5:
                    st.error("Опишіть проблему (мінімум 5 символів)")
                elif recent >= 5:
                    st.error("Ліміт: не більше 5 звернень на годину")
                else:
                    with DB_LOCK, db() as con:
                        con.execute("INSERT INTO reports(ts,consumer_id,line_id,category,text) VALUES(?,?,?,?,?)",
                                    (now_iso(), c["id"], c["line_id"], cat, txt.strip()))
                    st.success("Звернення надіслано")
        mine = qdf("SELECT id AS №, ts AS Час, category AS Тема, text AS Опис, status AS Статус "
                   "FROM reports WHERE consumer_id=? ORDER BY id DESC LIMIT 50", (c["id"],))
        if not mine.empty:
            mine["Статус"] = mine["Статус"].map(REPORT_STATUS)
            mine["Час"] = mine["Час"].map(fmt_dt)
            st.dataframe(mine, use_container_width=True, hide_index=True)

    with tabs[5]:
        with st.form("profile"):
            a, b = st.columns(2)
            email = a.text_input("Email", c["email"] or "")
            phone = b.text_input("Телефон", c["phone"] or "")
            tg = a.text_input("Telegram chat_id", c["telegram_chat"] or "")
            st.write("Канали сповіщень")
            e = st.checkbox("Email", bool(c["ch_email"]))
            sm = st.checkbox("SMS", bool(c["ch_sms"]))
            t = st.checkbox("Telegram", bool(c["ch_tg"]))
            if st.form_submit_button("Зберегти"):
                email, phone, tg = email.strip(), phone.strip(), tg.strip()
                if email and "@" not in email:
                    st.error("Некоректний email")
                elif (e and not email) or (sm and not phone) or (t and not tg):
                    st.error("Для кожного увімкненого каналу вкажіть контакт")
                else:
                    with DB_LOCK, db() as con:
                        con.execute("UPDATE consumers SET email=?,phone=?,telegram_chat=?,ch_email=?,ch_sms=?,"
                                    "ch_tg=? WHERE id=?", (email, phone, tg, int(e), int(sm), int(t), c["id"]))
                    st.toast("Профіль збережено")
                    st.rerun()
        with st.expander("🔑 Змінити PIN-код"):
            with st.form("pin"):
                old = st.text_input("Поточний PIN", type="password")
                new = st.text_input("Новий PIN (мін. 4 цифри)", type="password")
                new2 = st.text_input("Повторіть новий PIN", type="password")
                if st.form_submit_button("Змінити PIN"):
                    if not hmac.compare_digest(hash_pin(old, c["salt"]), c["pin_hash"]):
                        time.sleep(1)
                        st.error("Поточний PIN невірний")
                    elif len(new) < 4 or not new.isdigit():
                        st.error("Новий PIN: щонайменше 4 цифри")
                    elif new != new2:
                        st.error("PIN-коди не збігаються")
                    else:
                        salt = os.urandom(16).hex()
                        with DB_LOCK, db() as con:
                            con.execute("UPDATE consumers SET salt=?, pin_hash=? WHERE id=?",
                                        (salt, hash_pin(new, salt), c["id"]))
                        st.success("PIN змінено")


def admin_panel(cfg):
    st.subheader("Панель диспетчера")
    if not st.session_state.get("admin"):
        pw = st.text_input("Пароль адміністратора", type="password")
        if st.button("Увійти"):
            if hmac.compare_digest(pw.strip().encode(), str(cfg["ADMIN_PASSWORD"]).strip().encode()):
                st.session_state.admin = True
                st.rerun()
            time.sleep(1)
            st.error("Невірний пароль")
        if cfg["ADMIN_PASSWORD"] == ADMIN_PASSWORD:
            st.caption(f"Демо: пароль диспетчера {ADMIN_PASSWORD} (англійська розкладка, регістр важливий)")
            if st.button("⚡ Швидкий вхід (демо)"):
                st.session_state.admin = True
                st.rerun()
        return
    if cfg["ADMIN_PASSWORD"] == ADMIN_PASSWORD:
        st.warning("Пароль вшито в код — для безпеки задайте ADMIN_PASSWORD у secrets.")
    t1, t2, t3, t4, t5, t6, t7, t8 = st.tabs(["📡 Моніторинг", "👥 Споживачі", "📨 Журнал сповіщень", "🧪 Симулятор",
                                              "📝 Звернення", "🗺️ GIS-аналітика", "🕸️ Топологія",
                                              "📈 Надійність"])

    with t1:
        c1, c2 = st.columns([1, 3])
        if c1.button("🔄 Опитати зараз"):
            st.toast(poll_once(cfg))
        c2.info(("ДЕМО-режим (симулятор)" if cfg["DEMO"] else f"Джерело: {cfg['MONITORING_URL']}")
                + f" · інтервал {cfg['POLL_INTERVAL_SEC']} с")
        with DB_LOCK, db() as con:
            st.dataframe(pd.read_sql("SELECT * FROM incidents ORDER BY updated_at DESC", con),
                         use_container_width=True, hide_index=True)
            st.caption("Журнал опитувань")
            st.dataframe(pd.read_sql("SELECT ts,ok,message FROM poll_log ORDER BY id DESC LIMIT 15", con),
                         use_container_width=True, hide_index=True)

    with t2:
        with st.form("add_consumer", clear_on_submit=True):
            a, b = st.columns(2)
            acc, name = a.text_input("Особовий рахунок"), b.text_input("ПІБ")
            addr = a.text_input("Адреса (вулиця, будинок)")
            line = b.selectbox("Лінія мережі (населений пункт)", list(LINES), format_func=line_label)
            email, phone = a.text_input("Email"), b.text_input("Телефон")
            tg, pin = a.text_input("Telegram chat_id"), b.text_input("PIN (мін. 4 цифри)", type="password")
            if st.form_submit_button("Додати споживача"):
                if not (acc and name and line) or len(pin) < 4:
                    st.error("Заповніть рахунок, ПІБ, лінію та PIN")
                else:
                    salt = os.urandom(16).hex()
                    try:
                        with DB_LOCK, db() as con:
                            con.execute("INSERT INTO consumers(account,name,address,line_id,salt,pin_hash,"
                                        "email,phone,telegram_chat) VALUES(?,?,?,?,?,?,?,?,?)",
                                        (acc, name, f"{SETTLEMENTS[LINES[line]][0]}, {addr}", line, salt, hash_pin(pin, salt),
                                         email, phone, tg))
                        st.success("Додано")
                    except sqlite3.IntegrityError:
                        st.error("Такий рахунок уже існує")
        with DB_LOCK, db() as con:
            st.dataframe(pd.read_sql("SELECT account,name,address,line_id,email,phone,ch_email,ch_sms,ch_tg "
                                     "FROM consumers", con), use_container_width=True, hide_index=True)

    with t3:
        with DB_LOCK, db() as con:
            st.dataframe(pd.read_sql(
                "SELECT n.ts,n.incident_id,c.name,c.line_id,n.channel,n.status,n.detail FROM notif_log n "
                "JOIN consumers c ON c.id=n.consumer_id ORDER BY n.id DESC LIMIT 200", con),
                use_container_width=True, hide_index=True)

    with t4:
        if not cfg["DEMO"]:
            st.info("Симулятор доступний лише в демо-режимі.")
        else:
            sim = get_simulator()
            line = node_picker("sim")
            kind = st.radio("Тип", list(KINDS), format_func=KINDS.get, horizontal=True)
            title = st.text_input("Заголовок", "Пошкодження кабелю")
            hours = st.slider("Тривалість, год", 1, 12, 4)
            if st.button("➕ Створити подію"):
                now = datetime.now(timezone.utc)
                start = now if kind == "outage" else now + timedelta(hours=24)
                sim.add(kind, line, title, "Створено симулятором.", start, start + timedelta(hours=hours),
                        "active" if kind == "outage" else "scheduled")
                st.success("Створено — буде підхоплено при наступному опитуванні")
            open_ids = [i for i, v in sim.incidents.items() if v["status"] != "resolved"]
            rid = st.selectbox("Закрити подію", [""] + open_ids)
            if rid and st.button("✅ Позначити усуненою"):
                sim.resolve(rid)
                st.success("Статус оновлено")
            sched = [i for i, v in sim.incidents.items() if v["status"] == "scheduled"]
            sch_id = st.selectbox("Розпочати заплановані роботи", [""] + sched)
            if sch_id and st.button("▶️ Розпочати роботи"):
                sim.start(sch_id)
                st.success("Роботи розпочато — відключення буде враховано в SAIDI/SAIFI")
            st.divider()
            st.markdown("**Хвиля скарг споживачів** (для теплової карти) — навколо вузла, обраного вище")
            nwave = st.slider("Кількість скарг", 5, 80, 40, key="wave_n")
            w1, w2 = st.columns(2)
            if w1.button("📣 Згенерувати скарги"):
                st.success(f"Додано скарг: {gen_complaints(line, nwave)}")
            if w2.button("🧹 Видалити демо-скарги"):
                with DB_LOCK, db() as con:
                    con.execute("DELETE FROM reports WHERE consumer_id=0")
                st.success("Демо-скарги видалено")

    with t5:
        df = qdf("SELECT r.id, r.ts, COALESCE(c.account,'—') AS account, COALESCE(c.name,'Демо-абонент') AS name, "
                 "r.line_id, r.category, r.text, r.status FROM reports r "
                 "LEFT JOIN consumers c ON c.id=r.consumer_id ORDER BY r.id DESC LIMIT 200")
        if df.empty:
            st.info("Звернень поки немає.")
        else:
            st.dataframe(df.assign(status=df["status"].map(REPORT_STATUS)), use_container_width=True,
                         hide_index=True)
            r1, r2, r3 = st.columns(3)
            rid = r1.selectbox("Звернення №", df["id"].tolist())
            new = r2.selectbox("Статус", list(REPORT_STATUS), format_func=REPORT_STATUS.get)
            if r3.button("Оновити статус"):
                with DB_LOCK, db() as con:
                    con.execute("UPDATE reports SET status=? WHERE id=?", (new, int(rid)))
                st.rerun()

    with t6:
        g1, g2, g3 = st.columns(3)
        hours = g1.slider("Вікно скарг, год", 1, 24, 3)
        thr = g2.slider("Поріг кластера (скарг на фідер)", 2, 30, 4)
        closed = g3.checkbox("Враховувати закриті звернення", False)
        opts = st.multiselect("Шари карти", ["Підстанції 110/35 кВ", "Лінії (підстанція→фідер→ТП)", "ТП 0.4 кВ",
                                             "Теплова карта скарг"],
                              default=["Підстанції 110/35 кВ", "Теплова карта скарг"], key="gis_layers")
        res = grid_states()
        pts = complaint_points(hours, closed)
        st.pydeck_chart(network_map(res, settlement_states(res), subs="Підстанції 110/35 кВ" in opts,
                                    edges="Лінії (підстанція→фідер→ТП)" in opts, tps="ТП 0.4 кВ" in opts,
                                    heat=pts if "Теплова карта скарг" in opts else None),
                        use_container_width=True)
        st.caption(f"Скарг у вікні {hours} год: **{len(pts)}** · 🟢 норма · 🟠 планові роботи · 🔴 аварія · "
                   "тепла пляма — концентрація скарг")
        clusters, warns = complaint_clusters(pts, res, thr)
        for w in warns:
            st.error(w)
        if clusters.empty:
            st.info("Скарг у вибраному вікні немає. Згенеруйте їх у вкладці «Симулятор».")
        else:
            st.markdown("**Кластери скарг за фідерами**")
            st.dataframe(clusters, use_container_width=True, hide_index=True)

    with t7:
        res = grid_states()
        sub = st.selectbox("Підстанція", list(SUBSTATIONS), format_func=lambda i: GRID[i]["name"], key="topo_sub")
        st.graphviz_chart(grid_dot(sub, res), use_container_width=True)
        st.caption("🟢 норма · 🟠 планові роботи · 🔴 аварія/знеструмлення · пунктир — стан успадковано від вищого вузла (каскад)")
        st.divider()
        st.markdown("**Моделювання каскадного відключення (what-if)**")
        node = node_picker("wi")
        rep_ = cascade_report(node)
        k1, k2, k3 = st.columns(3)
        k1.metric("Фідерів без напруги", len(rep_["feeders"]))
        k2.metric("ТП без напруги", len(rep_["tps"]))
        k3.metric("Споживачів у реєстрі", len(rep_["consumers"]))
        if rep_["consumers"]:
            st.dataframe(pd.DataFrame([{"Рахунок": r["account"], "ПІБ": r["name"], "Адреса": r["address"],
                                        "ТП": GRID[tp_of(r["account"], r["line_id"])]["name"]}
                                       for r in rep_["consumers"]]), use_container_width=True, hide_index=True)
        if cfg["DEMO"] and st.button("⚡ Створити аварію на цьому вузлі (симулятор)"):
            now = datetime.now(timezone.utc)
            get_simulator().add("outage", node, f"Аварія: {GRID[node]['name']}", "Створено з розділу «Топологія».",
                                now, now + timedelta(hours=4), "active")
            st.success("Створено — буде підхоплено при наступному опитуванні (або натисніть «Опитати зараз»)")

    with t8:
        reliability_tab(cfg)


def inc_level(r) -> int:
    return 3 if (r["kind"] == "outage" and r["status"] == "active") else 2


def grid_states(rows=None) -> dict:
    """Стан кожного вузла з каскадом: подія на вищому вузлі успадковується всіма нижчими."""
    if rows is None:
        rows = q("SELECT * FROM incidents WHERE status!='resolved'")
    by_node = {}
    for r in rows:
        by_node.setdefault(r["line_id"], []).append(r)
    res = {}
    for nid, n in GRID.items():
        own = by_node.get(nid, [])
        lvl = max((inc_level(r) for r in own), default=0)
        dark = any(r["status"] == "active" for r in own)
        top = max(own, key=inc_level) if own else None
        cause, src, inh = (top["title"] if top else None), (nid if own else None), False
        p = res.get(n["parent"])
        if p and (p["level"] > lvl or (p["dark"] and not dark)):
            lvl, dark, cause, src, inh = max(lvl, p["level"]), dark or p["dark"], p["cause"], p["src"], True
        res[nid] = dict(level=lvl, dark=dark, cause=cause, src=src, inherited=inh)
    return res


def settlement_states(res: dict) -> dict:
    counts = {}
    for r in q("SELECT line_id, COUNT(*) AS n FROM consumers GROUP BY line_id"):
        code = LINES.get(r["line_id"])
        if code:
            counts[code] = counts.get(code, 0) + r["n"]
    out = {}
    for code in SETTLEMENTS:
        tps = [i for i in GRID if i.startswith(f"TP-{code}-")]
        out[code] = dict(level=max(res[i]["level"] for i in tps), tp_total=len(tps),
                         tp_dark=sum(res[i]["dark"] for i in tps), consumers=counts.get(code, 0))
    return out


def state_text(s: dict) -> str:
    t = LEVELS[s["level"]] + (" · знеструмлено" if s["dark"] else "")
    if s["cause"]:
        t += "<br/>Причина: " + _html.escape(str(s["cause"])) + (" (каскад від вищого вузла)" if s["inherited"] else "")
    return t


def network_map(res, sst, subs=False, edges=False, tps=False, heat=None, zoom=7.2) -> pdk.Deck:
    layers = []
    if heat is not None and not heat.empty:
        layers.append(pdk.Layer("HeatmapLayer", data=heat, get_position="[lon, lat]", get_weight="weight",
                                radius_pixels=55, intensity=2, threshold=0.03, aggregation='"SUM"'))
    if edges:
        data = []
        for nid, n in GRID.items():
            if n["parent"]:
                par, s = GRID[n["parent"]], res[nid]
                col = COLORS[3] if s["dark"] else COLORS[2] if s["level"] == 2 else [120, 130, 140, 120]
                data.append(dict(slon=par["lon"], slat=par["lat"], dlon=n["lon"], dlat=n["lat"], color=col))
        layers.append(pdk.Layer("LineLayer", data=pd.DataFrame(data), get_source_position="[slon, slat]",
                                get_target_position="[dlon, dlat]", get_color="color", get_width=2,
                                width_min_pixels=1))
    layers.append(pdk.Layer(
        "ScatterplotLayer", pickable=True, stroked=True, get_position="[lon, lat]", get_fill_color="color",
        get_line_color=[255, 255, 255], line_width_min_pixels=2, radius_min_pixels=7, radius_max_pixels=20,
        get_radius="radius",
        data=pd.DataFrame([dict(
            lon=v[3], lat=v[2], radius=3500, color=COLORS[sst[c]["level"]],
            tip=f"<b>{v[0]}</b> ({v[1]} р-н)<br/>{LEVELS[sst[c]['level']]}<br/>"
                f"Знеструмлено ТП: {sst[c]['tp_dark']}/{sst[c]['tp_total']}<br/>Споживачів у реєстрі: {sst[c]['consumers']}")
            for c, v in SETTLEMENTS.items()])))
    if tps:
        layers.append(pdk.Layer(
            "ScatterplotLayer", pickable=True, get_position="[lon, lat]", get_fill_color="color", get_radius=400,
            radius_min_pixels=3, radius_max_pixels=8,
            data=pd.DataFrame([dict(lon=n["lon"], lat=n["lat"], color=COLORS[res[i]["level"]],
                                    tip=f"<b>{n['name']}</b><br/>{state_text(res[i])}")
                               for i, n in GRID.items() if n["type"] == "tp"])))
    if subs:
        layers.append(pdk.Layer(
            "ScatterplotLayer", pickable=True, stroked=True, get_position="[lon, lat]", get_fill_color="color",
            get_line_color=[20, 20, 20], line_width_min_pixels=3, get_radius=5000, radius_min_pixels=11,
            radius_max_pixels=26,
            data=pd.DataFrame([dict(lon=n["lon"], lat=n["lat"], color=COLORS[res[i]["level"]],
                                    tip=f"<b>{n['name']}</b><br/>{state_text(res[i])}")
                               for i, n in GRID.items() if n["type"] == "sub"])))
    return pdk.Deck(layers=layers, map_style="light", tooltip={"html": "{tip}"},
                    initial_view_state=pdk.ViewState(latitude=49.05, longitude=28.5, zoom=zoom, pitch=0))


def node_picker(key: str) -> str:
    t = st.radio("Рівень вузла", list(NODE_TYPES), format_func=NODE_TYPES.get, horizontal=True, key=f"{key}_t")
    ids = [i for i, n in GRID.items() if n["type"] == t]
    return st.selectbox("Вузол", ids, format_func=lambda i: GRID[i]["name"], key=f"{key}_n")


def cascade_report(node: str) -> dict:
    ds = descendants(node)
    return dict(feeders=[i for i in ds if GRID[i]["type"] == "feeder"],
                tps=[i for i in ds if GRID[i]["type"] == "tp"], consumers=consumers_under(node))


def complaint_points(hours: int, include_closed: bool = False) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(microsecond=0).isoformat()
    rows = q("SELECT r.id, r.line_id, c.account, c.line_id AS cline FROM reports r "
             "LEFT JOIN consumers c ON c.id=r.consumer_id WHERE r.ts>? "
             + ("" if include_closed else "AND r.status!='closed'"), (since,))
    pts = []
    for r in rows:
        if r["account"] and r["cline"] in GRID:
            node = tp_of(r["account"], r["cline"])
        elif r["line_id"] in GRID:
            node = r["line_id"]
        else:
            continue
        n = GRID[node]
        j = [(int(hashlib.md5(f"{r['id']}{k}".encode()).hexdigest()[:6], 16) % 1000) / 1000 - 0.5 for k in "ab"]
        feeder = node if n["type"] == "feeder" else (n["parent"] if n["type"] == "tp" else None)
        pts.append(dict(lat=n["lat"] + j[0] * 0.008, lon=n["lon"] + j[1] * 0.012, weight=1, feeder=feeder))
    return pd.DataFrame(pts, columns=["lat", "lon", "weight", "feeder"])


def complaint_clusters(pts: pd.DataFrame, res: dict, thr: int):
    if pts.empty or pts["feeder"].dropna().empty:
        return pd.DataFrame(), []
    cnt = pts.groupby("feeder").size().sort_values(ascending=False)
    rows, flagged = [], {}
    for f, n in cnt.items():
        lvl = res[f]["level"]
        if n >= thr and lvl == 0:
            flagged.setdefault(GRID[f]["parent"], []).append(f)
        rows.append({"Фідер": GRID[f]["name"], "Скарг": int(n), "Стан у системі": LEVELS[lvl],
                     "Оцінка": "⚠️ Імовірна незареєстрована аварія" if n >= thr and lvl == 0
                     else "✅ Збігається із зареєстрованою подією" if n >= thr else "Спостереження"})
    warns = [f"🚨 Скарги з {len(fs)} фідерів під {GRID[sb]['name']} — імовірна аварія на підстанції, перевірте її."
             for sb, fs in flagged.items() if len(fs) >= 2]
    return pd.DataFrame(rows), warns


def gen_complaints(node: str, n: int) -> int:
    tps = [i for i in descendants(node) if GRID[i]["type"] == "tp"]
    if not tps:
        return 0
    now = datetime.now(timezone.utc)
    with DB_LOCK, db() as con:
        for _ in range(n):
            ts = (now - timedelta(minutes=random.randint(0, 30))).replace(microsecond=0).isoformat()
            con.execute("INSERT INTO reports(ts,consumer_id,line_id,category,text) VALUES(?,?,?,?,?)",
                        (ts, 0, random.choice(tps), REPORT_CATEGORIES[0], "Демо-скарга (симулятор)"))
    return n


def grid_dot(sub_id: str, res: dict) -> str:
    col = {0: "#2ea043", 2: "#fb8c00", 3: "#e53935"}
    out = ["digraph G {", '  rankdir=LR; bgcolor="transparent";',
           '  node [shape=box, fontname="Helvetica", fontsize=10, fontcolor="white", color="#555555"];',
           '  edge [color="#8b949e"];']
    for nid in descendants(sub_id):
        n, st_ = GRID[nid], res[nid]
        label = {"sub": n["name"], "feeder": f"Фідер {nid}", "tp": f"ТП {nid[3:]}"}[n["type"]]
        if st_["dark"]:
            label += "\\n⚡ знеструмлено"
        style = "rounded,filled,dashed" if st_["inherited"] else "rounded,filled"
        out.append(f'  "{nid}" [label="{label}", fillcolor="{col[st_["level"]]}", style="{style}"];')
        if n["parent"]:
            out.append(f'  "{n["parent"]}" -> "{nid}" [color="{"#e53935" if st_["dark"] else "#8b949e"}"];')
    for c in consumers_under(sub_id):
        tp = tp_of(c["account"], c["line_id"])
        nm = str(c["name"]).replace('"', "'")
        out.append(f'  "C{c["account"]}" [label="👤 {nm}", shape=ellipse, style="filled", '
                   f'fillcolor="{col[res[tp]["level"]]}"];')
        out.append(f'  "{tp}" -> "C{c["account"]}";')
    out.append("}")
    return "\n".join(out)


# ───────────────────────── Надійність електропостачання (SAIFI / SAIDI / CAIDI) ─────────────────────────
RAIONS = sorted({v[1] for v in SETTLEMENTS.values()})
KIND_LABELS = {"outage": "Аварійне", "planned": "Планове"}
TYPE_FILTERS = {"Аварійні (незаплановані)": ("outage",), "Планові": ("planned",), "Усі": ("outage", "planned")}
CAUSES = ["Пошкодження повітряної лінії", "Зношення обладнання", "Грозові/погодні умови",
          "Пошкодження кабелю", "Перевантаження", "Збій релейного захисту"]


def pdt(v):
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def iso_utc(d: datetime) -> str:
    return d.astimezone(timezone.utc).replace(microsecond=0).isoformat()


@functools.lru_cache(maxsize=None)
def tps_under(node: str) -> tuple:
    return tuple(i for i in descendants(node) if GRID[i]["type"] == "tp")


def tp_raion(tp: str) -> str:
    return SETTLEMENTS[node_code(tp)][1]


def customers_total(raion=None) -> int:
    return sum(g["customers"] for i, g in GRID.items() if g["type"] == "tp" and (raion is None or tp_raion(i) == raion))


def track_interruption(inc: dict):
    """Фіксує фактичні відключення (початок/відновлення) для обчислення індексів надійності."""
    st_dt, up_dt = pdt(inc.get("starts_at")), pdt(inc["updated_at"]) or datetime.now(timezone.utc)
    with DB_LOCK, db() as con:
        last = con.execute("SELECT id, end_ts FROM interruptions WHERE incident_id=? AND synthetic=0 "
                           "ORDER BY id DESC LIMIT 1", (inc["id"],)).fetchone()
        if inc["status"] == "active" and (not last or last["end_ts"]):
            begin = st_dt if st_dt and st_dt <= up_dt else up_dt
            con.execute("INSERT INTO interruptions(incident_id,node_id,kind,start_ts,end_ts,cause) VALUES(?,?,?,?,NULL,?)",
                        (inc["id"], inc["line_id"], inc["kind"], iso_utc(begin), inc["title"]))
        elif inc["status"] == "resolved":
            if last and not last["end_ts"]:
                con.execute("UPDATE interruptions SET end_ts=? WHERE id=?", (iso_utc(up_dt), last["id"]))
            elif not last and st_dt and st_dt < up_dt:
                con.execute("INSERT INTO interruptions(incident_id,node_id,kind,start_ts,end_ts,cause) VALUES(?,?,?,?,?,?)",
                            (inc["id"], inc["line_id"], inc["kind"], iso_utc(st_dt), iso_utc(up_dt), inc["title"]))


def seed_history(days: int = 90, n: int = 220, seed: int = 42) -> int:
    """Демо-історія відключень: «слабкі» фідери, пара штормових днів, планові роботи."""
    rng = random.Random(seed)
    feeders = [i for i, g in GRID.items() if g["type"] == "feeder"]
    weak = set(rng.sample(feeders, 8))
    weights = [8 if f in weak else 1 for f in feeders]
    now = datetime.now(timezone.utc)
    recs = []

    def add(node, kind, start, dur, cause):
        if start + timedelta(minutes=dur) > now:
            start = now - timedelta(minutes=dur + 1)
        recs.append((f"HIST-{len(recs) + 1:04d}", node, kind, iso_utc(start),
                     iso_utc(start + timedelta(minutes=dur)), cause, 1))

    for _ in range(n):
        start = now - timedelta(seconds=rng.uniform(3600, days * 86400))
        f, r, planned = rng.choices(feeders, weights)[0], rng.random(), rng.random() < 0.15
        node = (rng.choice(list(SUBSTATIONS)) if r < 0.04 and not planned
                else rng.choice(tps_under(f)) if r < 0.20 else f)
        if planned:
            add(node, "planned", start.replace(hour=rng.randint(8, 11), minute=0),
                rng.choice([120, 180, 240, 300, 360]) + rng.randint(-20, 20), "Плановий ремонт обладнання")
        else:
            cause = rng.choice(CAUSES[:2]) if f in weak else rng.choices(CAUSES, [30, 25, 15, 12, 10, 8])[0]
            add(node, "outage", start, min(max(rng.lognormvariate(math.log(80), 0.8), 4), 720), cause)
    for _ in range(2):  # шторм у районі
        day, raion = now - timedelta(days=rng.randint(3, days - 1)), rng.choice(RAIONS)
        fs = [f for f in feeders if SETTLEMENTS[f.split("-")[0]][1] == raion]
        for f in rng.sample(fs, min(len(fs), rng.randint(5, 9))):
            add(f, "outage", day.replace(hour=rng.randint(14, 19), minute=rng.randint(0, 59)),
                rng.randint(40, 300), "Грозові/погодні умови")
    with DB_LOCK, db() as con:
        con.execute("DELETE FROM interruptions WHERE synthetic=1")
        con.executemany("INSERT INTO interruptions(incident_id,node_id,kind,start_ts,end_ts,cause,synthetic) "
                        "VALUES(?,?,?,?,?,?,?)", recs)
    return len(recs)


FRAME_COLS = ["int_id", "node", "kind", "start", "dur", "tp", "feeder", "raion", "customers", "cause", "ongoing"]


def interruption_frame(start, end, kinds, min_min=3, raion=None) -> pd.DataFrame:
    """Один рядок на пару (відключення, ТП): вузол аварії каскадно охоплює всі ТП нижче."""
    now, recs = datetime.now(timezone.utc), []
    for r in q("SELECT * FROM interruptions WHERE start_ts>=? AND start_ts<?", (iso_utc(start), iso_utc(end))):
        if r["kind"] not in kinds or r["node_id"] not in GRID:
            continue
        a, b = pdt(r["start_ts"]), (pdt(r["end_ts"]) if r["end_ts"] else now)
        if not a or not b or (b - a).total_seconds() / 60 < min_min:
            continue
        dur = (b - a).total_seconds() / 60
        for tp in tps_under(r["node_id"]):
            if raion and tp_raion(tp) != raion:
                continue
            recs.append(dict(int_id=r["id"], node=r["node_id"], kind=r["kind"], start=a, dur=dur, tp=tp,
                             feeder=GRID[tp]["parent"], raion=tp_raion(tp), customers=GRID[tp]["customers"],
                             cause=r["cause"], ongoing=not r["end_ts"]))
    df = pd.DataFrame(recs, columns=FRAME_COLS)
    df["start"] = pd.to_datetime(df["start"], utc=True)
    return df


def kpis(df: pd.DataFrame, n_total: int, days: int) -> dict:
    if df.empty or n_total <= 0:
        return dict(saifi=0.0, saidi=0.0, caidi=0.0, asai=100.0, events=0)
    saifi = df["customers"].sum() / n_total
    saidi = (df["customers"] * df["dur"]).sum() / n_total
    return dict(saifi=saifi, saidi=saidi, caidi=saidi / saifi if saifi else 0.0,
                asai=100 * (1 - saidi / (days * 1440)), events=int(df["int_id"].nunique()))


def risk_label(score: float, events: int) -> str:
    return "Високий" if score >= 2.5 and events >= 3 else "Підвищений" if score >= 1.5 and events >= 2 else "Норма"


def reliability_tab(cfg):
    st.markdown("**Індекси надійності електропостачання: SAIFI / SAIDI / CAIDI**")
    c1, c2, c3, c4 = st.columns(4)
    days = c1.radio("Період, діб", [30, 90], horizontal=True, key="rel_days")
    scope = c2.selectbox("Територія", ["Вся область"] + RAIONS, key="rel_scope")
    typ = c3.selectbox("Тип відключень", list(TYPE_FILTERS), key="rel_type")
    min_min = c4.slider("Мін. тривалість, хв", 0, 30, 3, key="rel_min")
    raion, kinds = (None if scope == "Вся область" else scope), TYPE_FILTERS[typ]
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    n_total = customers_total(raion)
    df = interruption_frame(start, now + timedelta(minutes=1), kinds, min_min, raion)
    prev = interruption_frame(start - timedelta(days=days), start, kinds, min_min, raion)
    k, kp, has_prev = kpis(df, n_total, days), kpis(prev, n_total, days), not prev.empty

    def delta(key, fmt):
        return fmt.format(k[key] - kp[key]) if has_prev else None

    m = st.columns(5)
    m[0].metric("SAIFI", f"{k['saifi']:.2f}", delta("saifi", "{:+.2f}"), delta_color="inverse",
                help="Середня кількість відключень на одного споживача за період")
    m[1].metric("SAIDI", f"{k['saidi']:.0f} хв", delta("saidi", "{:+.0f} хв"), delta_color="inverse",
                help=f"Середня сумарна тривалість відключень на споживача ≈ {k['saidi'] / 60:.1f} год")
    m[2].metric("CAIDI", f"{k['caidi']:.0f} хв", delta("caidi", "{:+.0f} хв"), delta_color="inverse",
                help="Середній час відновлення живлення = SAIDI / SAIFI")
    m[3].metric("ASAI", f"{k['asai']:.3f} %", delta("asai", "{:+.3f} %"),
                help="Середня доступність електропостачання")
    m[4].metric("Відключень", k["events"], f"{k['events'] - kp['events']:+d}" if has_prev else None,
                delta_color="inverse")
    st.caption(f"SAIFI = Σ(споживачі × відключення) / N · SAIDI = Σ(споживачі × хвилини) / N · CAIDI = SAIDI / SAIFI, "
               f"N = {n_total:,} споживачів ({scope}; кількість абонентів на ТП — модель, замініть даними білінгу). "
               f"Враховано відключення ≥ {min_min} хв; триваючі рахуються до поточного моменту. "
               + ("Зміна — відносно попереднього періоду такої ж довжини." if has_prev else "Попередній період без даних."))

    if cfg["DEMO"]:
        with st.expander("🧪 Демо-дані історії відключень"):
            d1, d2 = st.columns(2)
            if d1.button("Згенерувати історію за 90 діб"):
                st.success(f"Створено записів: {seed_history()}")
                st.rerun()
            if d2.button("Видалити демо-історію"):
                with DB_LOCK, db() as con:
                    con.execute("DELETE FROM interruptions WHERE synthetic=1")
                st.rerun()
    if df.empty:
        st.info("За вибраними параметрами відключень немає.")
        return
    if px is None:
        st.warning("Для графіків встановіть plotly: `pip install plotly` (додайте у requirements.txt).")
        return

    freq = "D" if days <= 30 else "W"
    work = df.assign(cm=df["customers"] * df["dur"], b=df["start"].dt.tz_convert(None).dt.to_period(freq))
    idx = pd.period_range(start.replace(tzinfo=None), now.replace(tzinfo=None), freq=freq)
    agg = work.groupby("b").agg(cust=("customers", "sum"), cm=("cm", "sum")).reindex(idx, fill_value=0)
    xs = [p.start_time for p in agg.index]

    st.markdown(f"##### Тренд ({'по днях' if freq == 'D' else 'по тижнях'})")
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_bar(x=xs, y=agg["cm"] / n_total, name="SAIDI, хв", marker_color="#e53935")
    fig.add_scatter(x=xs, y=agg["cust"] / n_total, name="SAIFI", mode="lines+markers",
                    line=dict(color="#1f77b4", width=3), secondary_y=True)
    fig.update_yaxes(title_text="SAIDI, хв на споживача", secondary_y=False)
    fig.update_yaxes(title_text="SAIFI, відключень на споживача", secondary_y=True)
    fig.update_layout(template="plotly_white", height=380, margin=dict(t=20, b=20),
                      legend=dict(orientation="h", y=1.12))
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("##### Повторюваність відключень за районами")
    ev = work.drop_duplicates(["int_id", "raion"])
    bk = ev.groupby(["raion", "kind"]).size().reset_index(name="Подій")
    bk["Тип"] = bk["kind"].map(KIND_LABELS)
    g1, g2 = st.columns(2)
    f1 = px.bar(bk, x="raion", y="Подій", color="Тип", barmode="stack", template="plotly_white",
                color_discrete_map={"Аварійне": "#e53935", "Планове": "#fb8c00"},
                labels={"raion": "Район"}, title="Кількість відключень")
    f1.update_layout(height=360, margin=dict(t=50, b=20), legend=dict(orientation="h", y=-0.25))
    g1.plotly_chart(f1, use_container_width=True)
    rr = work.groupby("raion").agg(cust=("customers", "sum"), cm=("cm", "sum")).reset_index()
    rr["N"] = rr["raion"].map(customers_total)
    rr["SAIFI"], rr["SAIDI"] = rr["cust"] / rr["N"], rr["cm"] / rr["N"]
    f2 = px.bar(rr.sort_values("SAIDI"), x="SAIDI", y="raion", orientation="h", color="SAIFI", text_auto=".0f",
                color_continuous_scale="YlOrRd", template="plotly_white", labels={"raion": "Район", "SAIDI": "SAIDI, хв"},
                title="SAIDI за районами (колір — SAIFI)")
    f2.update_layout(height=360, margin=dict(t=50, b=20))
    g2.plotly_chart(f2, use_container_width=True)
    labels = [p.start_time.strftime("%d.%m") for p in idx]
    hm = ev.assign(bl=ev["b"].dt.start_time.dt.strftime("%d.%m")).pivot_table(
        index="raion", columns="bl", values="int_id", aggfunc="count", fill_value=0)
    hm = hm.reindex(index=[raion] if raion else RAIONS, columns=labels, fill_value=0)
    f3 = px.imshow(hm, aspect="auto", color_continuous_scale="YlOrRd", template="plotly_white",
                   labels=dict(x="Початок періоду", y="Район", color="Подій"),
                   title="Теплова матриця: відключення за районами та часом")
    f3.update_layout(height=300, margin=dict(t=50, b=20))
    st.plotly_chart(f3, use_container_width=True)

    st.markdown(f"##### Найбільш проблемні (зношені) фідери за {days} діб")
    topn = st.slider("Показати фідерів", 5, 20, 10, key="rel_top")
    fd = work[work["node"].map(lambda n: GRID[n]["type"]).isin(["feeder", "tp"])]
    fs = (fd.drop_duplicates(["int_id", "feeder"]).groupby("feeder").agg(events=("int_id", "nunique"), down=("dur", "sum"))
          .join(fd.groupby("feeder")["cm"].sum().rename("cm")))
    all_f = [f for f, g in GRID.items() if g["type"] == "feeder" and (raion is None or tp_raion(tps_under(f)[0]) == raion)]
    fs = fs.reindex(all_f, fill_value=0)
    fs["score"] = fs["events"] / (fs["events"].mean() or 1)
    fs["risk"] = [risk_label(a, int(b)) for a, b in zip(fs["score"], fs["events"])]
    fs["name"] = [GRID[i]["name"] for i in fs.index]
    top = fs.sort_values(["events", "cm"], ascending=False).head(topn)
    f4 = px.bar(top.iloc[::-1], x="events", y="name", orientation="h", color="risk", text="events",
                color_discrete_map={"Високий": "#e53935", "Підвищений": "#fb8c00", "Норма": "#2ea043"},
                template="plotly_white", labels={"events": "Відключень", "name": "", "risk": "Ризик"})
    f4.update_layout(height=max(320, 32 * len(top)), margin=dict(t=20, b=20), legend=dict(orientation="h", y=1.08))
    st.plotly_chart(f4, use_container_width=True)
    icon = {"Високий": "🔴 Високий", "Підвищений": "🟠 Підвищений", "Норма": "🟢 Норма"}
    tbl = pd.DataFrame({"Фідер": top["name"], "Відключень": top["events"], "Сумарно, год": (top["down"] / 60).round(1),
                        "Інтервал між, діб": [round(days / e, 1) if e else None for e in top["events"]],
                        "Індекс зношення": top["score"].round(2), "Ризик": top["risk"].map(icon)})
    st.dataframe(tbl, use_container_width=True, hide_index=True)
    st.caption("Індекс зношення = кількість відключень фідера / середня кількість по фідерах (≥2.5 — високий, ≥1.5 — підвищений). "
               "Відключення вищого рівня (підстанція) у рейтинг фідерів не входять.")
    wc = work.drop_duplicates("int_id")["cause"].value_counts().reset_index()
    wc.columns = ["Причина", "Подій"]
    f5 = px.bar(wc.iloc[::-1], x="Подій", y="Причина", orientation="h", template="plotly_white", title="Причини відключень")
    f5.update_layout(height=300, margin=dict(t=50, b=20))
    st.plotly_chart(f5, use_container_width=True)
    with st.expander("📋 Реєстр відключень"):
        reg = work.groupby("int_id").agg(Початок=("start", "min"), Вузол=("node", "first"), Тип=("kind", "first"),
                                         Хвилин=("dur", "first"), Споживачів=("customers", "sum"),
                                         Причина=("cause", "first")).reset_index()
        reg["Вузол"], reg["Тип"] = reg["Вузол"].map(line_label), reg["Тип"].map(KIND_LABELS)
        reg["Початок"], reg["Хвилин"] = reg["Початок"].dt.strftime("%d.%m.%Y %H:%M"), reg["Хвилин"].round(0)
        st.dataframe(reg, use_container_width=True, hide_index=True)
        st.download_button("⬇️ Завантажити CSV", reg.to_csv(index=False).encode("utf-8-sig"), "interruptions.csv", "text/csv")


def oblast_map():
    st.subheader("Карта мережі Вінницької області")

    @st.fragment(run_every=10)
    def live():
        rows = q("SELECT * FROM incidents WHERE status!='resolved'")
        res = grid_states(rows)
        sst = settlement_states(res)
        tp_ids = [i for i, n in GRID.items() if n["type"] == "tp"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Активні аварії", sum(r["kind"] == "outage" and r["status"] == "active" for r in rows))
        m2.metric("Планові роботи", sum(r["kind"] == "planned" for r in rows))
        m3.metric("Пункти в нормі", f"{sum(v['level'] == 0 for v in sst.values())}/{len(sst)}")
        m4.metric("ТП без напруги", f"{sum(res[i]['dark'] for i in tp_ids)}/{len(tp_ids)}")
        opts = st.multiselect("Шари", ["Підстанції 110/35 кВ", "Лінії (підстанція→фідер→ТП)", "ТП 0.4 кВ"],
                              default=["Підстанції 110/35 кВ"], key="pub_layers")
        st.pydeck_chart(network_map(res, sst, subs="Підстанції 110/35 кВ" in opts,
                                    edges="Лінії (підстанція→фідер→ТП)" in opts, tps="ТП 0.4 кВ" in opts),
                        use_container_width=True)
        st.caption("🟢 норма · 🟠 планові ремонти · 🔴 аварія. Наведіть курсор на маркер, щоб побачити деталі. "
                   "Аварія на підстанції чи фідері каскадно позначає всі підпорядковані ТП і пункти.")
        if rows:
            st.dataframe(pd.DataFrame([{
                "Район": SETTLEMENTS[node_code(r["line_id"])][1] if node_code(r["line_id"]) else "—",
                "Вузол мережі": line_label(r["line_id"]), "Тип": KINDS[r["kind"]], "Подія": r["title"],
                "Статус": STATUSES[r["status"]], "Початок": fmt_dt(r["starts_at"])} for r in rows]),
                use_container_width=True, hide_index=True)

    live()


def projects_page():
    st.subheader("Пов'язані проєкти")
    cols = st.columns(len(PROJECT_LINKS))
    for col, (name, url) in zip(cols, PROJECT_LINKS):
        col.link_button(f"🔗 {name}", url, use_container_width=True)
    st.divider()
    pick = st.selectbox("Переглянути вбудовано", [n for n, _ in PROJECT_LINKS])
    url = dict(PROJECT_LINKS)[pick]
    st.components.v1.iframe(url + ("&" if "?" in url else "?") + "embed=true", height=720, scrolling=True)
    st.caption("Якщо застосунок не відображається у рамці — відкрийте його кнопкою вище.")


def main():
    st.set_page_config(page_title="Сервіс інформування — Вінницька область", page_icon="⚡", layout="wide")
    cfg = load_config()
    init_db()
    with DB_LOCK, db() as con:
        if con.execute("SELECT COUNT(*) FROM consumers").fetchone()[0] == 0 and cfg["DEMO"]:
            salt = os.urandom(16).hex()
            con.execute("INSERT INTO consumers(account,name,address,line_id,salt,pin_hash,email,phone) "
                        "VALUES('1001','Іван Петренко','м. Вінниця, вул. Соборна, 12','VIN-2',?,?,'ivan@example.com',"
                        "'+380501112233')", (salt, hash_pin("1234", salt)))
    if cfg["DEMO"] and q("SELECT COUNT(*) AS n FROM interruptions")[0]["n"] == 0:
        seed_history()
    start_poller(tuple(sorted(cfg.items())))

    st.title("⚡ Сервіс інформування споживачів — Вінницька область")
    st.caption("Автоматичні сповіщення про планові ремонти та аварії на вашій лінії мережі "
               "(21 населений пункт, 6 районів)")
    mode = st.sidebar.radio("Розділ", ["Кабінет споживача", "Карта області", "Диспетчер", "Пов'язані проєкти"])
    st.sidebar.markdown("**Проєкти**")
    for name, url in PROJECT_LINKS:
        st.sidebar.link_button(f"🔗 {name}", url, use_container_width=True)
    st.sidebar.markdown(f"🔒 Канал даних: {'демо (підписаний симулятор)' if cfg['DEMO'] else 'HTTPS + HMAC'}")
    if mode == "Кабінет споживача":
        consumer_portal()
    elif mode == "Карта області":
        oblast_map()
    elif mode == "Диспетчер":
        admin_panel(cfg)
    else:
        projects_page()


main()
