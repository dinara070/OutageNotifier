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
import os
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import pandas as pd
import streamlit as st

try:
    import requests
except ImportError:  # потрібен лише для бойового режиму та Telegram
    requests = None

DB_PATH = os.environ.get("NOTIFY_DB", "notify.db")
DB_LOCK = threading.RLock()
MAX_SKEW_SEC = 300
KINDS = {"outage": "🚨 Аварія", "planned": "🛠️ Плановий ремонт"}
STATUSES = {"active": "Триває", "scheduled": "Заплановано", "resolved": "Усунено"}
DEMO_SECRET = "demo-secret-change-me"

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


def line_label(line: str) -> str:
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
    cfg["ADMIN_PASSWORD"] = cfg["ADMIN_PASSWORD"] or "admin"
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
    body = (f"Шановний(а) {c['name']}!\n\n{kind} на вашій лінії {line_label(inc['line_id'])} "
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
    with DB_LOCK, db() as con:
        consumers = con.execute("SELECT * FROM consumers WHERE line_id=?", (inc["line_id"],)).fetchall()
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
            f"_Оновлено: {fmt_dt(r['updated_at'])}_")


def consumer_portal():
    st.subheader("Кабінет споживача")
    if "consumer_id" not in st.session_state:
        with st.form("login"):
            acc = st.text_input("Номер особового рахунку")
            pin = st.text_input("PIN-код", type="password")
            if st.form_submit_button("Увійти"):
                with DB_LOCK, db() as con:
                    c = con.execute("SELECT * FROM consumers WHERE account=?", (acc.strip(),)).fetchone()
                ok = c and hmac.compare_digest(hash_pin(pin, c["salt"]), c["pin_hash"])
                if ok:
                    st.session_state.consumer_id = c["id"]
                    st.rerun()
                time.sleep(1)  # уповільнення підбору PIN
                st.error("Невірний рахунок або PIN")
        st.caption("Демо: рахунок 1001, PIN 1234" if load_config()["DEMO"] else "")
        return
    with DB_LOCK, db() as con:
        c = con.execute("SELECT * FROM consumers WHERE id=?", (st.session_state.consumer_id,)).fetchone()
    st.write(f"👤 **{c['name']}** · {c['address']} · лінія **{line_label(c['line_id'])}**")
    if st.button("Вийти"):
        del st.session_state["consumer_id"]
        st.rerun()

    @st.fragment(run_every=5)
    def live():
        with DB_LOCK, db() as con:
            rows = con.execute("SELECT * FROM incidents WHERE line_id=? ORDER BY "
                               "(status='resolved'), updated_at DESC", (c["line_id"],)).fetchall()
        incident_cards(rows)

    live()
    with st.expander("⚙️ Канали сповіщень"):
        e = st.checkbox("Email", bool(c["ch_email"]))
        s = st.checkbox("SMS", bool(c["ch_sms"]))
        t = st.checkbox("Telegram", bool(c["ch_tg"]))
        if st.button("Зберегти налаштування"):
            with DB_LOCK, db() as con:
                con.execute("UPDATE consumers SET ch_email=?,ch_sms=?,ch_tg=? WHERE id=?",
                            (int(e), int(s), int(t), c["id"]))
            st.toast("Збережено")
    with st.expander("📜 Мої сповіщення"):
        with DB_LOCK, db() as con:
            df = pd.read_sql("SELECT ts,incident_id,channel,status,detail FROM notif_log "
                             "WHERE consumer_id=? ORDER BY id DESC LIMIT 50", con, params=(c["id"],))
        st.dataframe(df, use_container_width=True, hide_index=True)


def admin_panel(cfg):
    st.subheader("Панель диспетчера")
    if not st.session_state.get("admin"):
        pw = st.text_input("Пароль адміністратора", type="password")
        if st.button("Увійти"):
            if hmac.compare_digest(pw, str(cfg["ADMIN_PASSWORD"])):
                st.session_state.admin = True
                st.rerun()
            time.sleep(1)
            st.error("Невірний пароль")
        return
    if cfg["ADMIN_PASSWORD"] == "admin":
        st.warning("Використовується пароль за замовчуванням — задайте ADMIN_PASSWORD у secrets.")
    t1, t2, t3, t4 = st.tabs(["📡 Моніторинг", "👥 Споживачі", "📨 Журнал сповіщень", "🧪 Симулятор"])

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
            line = st.selectbox("Лінія", list(LINES), format_func=line_label)
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


def oblast_map():
    st.subheader("Карта подій по Вінницькій області")

    @st.fragment(run_every=10)
    def live():
        with DB_LOCK, db() as con:
            rows = con.execute("SELECT * FROM incidents WHERE status!='resolved'").fetchall()
        base = pd.DataFrame([{"lat": v[2], "lon": v[3], "color": "#4a90d9", "size": 600}
                             for v in SETTLEMENTS.values()])
        ev = pd.DataFrame([{"lat": SETTLEMENTS[LINES[r["line_id"]]][2], "lon": SETTLEMENTS[LINES[r["line_id"]]][3],
                            "color": "#e53935" if r["kind"] == "outage" else "#fb8c00", "size": 1800}
                           for r in rows if r["line_id"] in LINES])
        m1, m2, m3 = st.columns(3)
        m1.metric("Активні аварії", sum(r["kind"] == "outage" and r["status"] == "active" for r in rows))
        m2.metric("Заплановані ремонти", sum(r["kind"] == "planned" for r in rows))
        with DB_LOCK, db() as con:
            m3.metric("Споживачів у реєстрі", con.execute("SELECT COUNT(*) FROM consumers").fetchone()[0])
        st.map(pd.concat([base, ev]), latitude="lat", longitude="lon", color="color", size="size", zoom=7)
        st.caption("🔵 населені пункти · 🔴 аварія · 🟠 плановий ремонт")
        if rows:
            st.dataframe(pd.DataFrame([{
                "Район": SETTLEMENTS[LINES[r["line_id"]]][1] if r["line_id"] in LINES else "—",
                "Лінія": line_label(r["line_id"]), "Тип": KINDS[r["kind"]], "Подія": r["title"],
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
