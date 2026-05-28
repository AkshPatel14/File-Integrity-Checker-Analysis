"""
File Integrity Checker
======================
USB Monitor + Folder Integrity Checker
SHA-256 · SQLite · Session Scan IDs · PDF Report · VirusTotal

Requirements:
    pip install customtkinter pywin32 plyer fpdf2 requests
"""

import customtkinter as ctk
import sqlite3, hashlib, os, stat as _stat_mod, threading, time, queue, sys
from datetime import datetime
from tkinter import messagebox, filedialog

try:
    import win32gui, win32con, win32api, win32com.client, pythoncom
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ══════════════════════ VIRUSTOTAL API KEY ══════════════════════
# Paste your VirusTotal API key here (get free key at virustotal.com)
VT_API_KEY = ""
# ════════════════════════════════════════════════════════════════

C = {
    "bg0":"#EBF4FF","bg1":"#DBEAFE","bg2":"#EFF6FF",
    "card":"#FFFFFF","card2":"#DBEAFE",
    "border":"#BFDBFE","border2":"#93C5FD","hover":"#E0EFFF",
    "cyan":"#1D4ED8","cyan_dim":"#1E40AF",
    "gold":"#D97706","gold_dim":"#B45309","purple":"#7C3AED",
    "green":"#059669","green_b":"#D1FAE5",
    "red":"#DC2626","red_b":"#FEE2E2",
    "yellow":"#D97706","yellow_b":"#FEF3C7",
    "orange":"#EA580C","orange_b":"#FFEDD5",
    "t0":"#1E3A5F","t1":"#2D5A8E","t2":"#4A7BA7","t3":"#93C5FD",
}
FONT_MONO = "Cascadia Code" if sys.platform=="win32" else "Courier New"
FONT_UI   = "Segoe UI"      if sys.platform=="win32" else "SF Pro Display"

# ══════════════════════ SESSION SCAN COUNTER ══════════════════════
_session_scan_counter = 0
def _next_session_scan_id():
    global _session_scan_counter
    _session_scan_counter += 1
    return _session_scan_counter

# ══════════════════════ VIRUSTOTAL ══════════════════════

def vt_check_hash(sha256_hash):
    if not REQUESTS_AVAILABLE:
        return {"status":"error","error_msg":"requests library not installed"}
    api_key = VT_API_KEY.strip()
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"status":"error","error_msg":"No API key configured"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"status":"unknown","malicious":0,"suspicious":0,
                    "undetected":0,"total":0,"score":"Not in database","error_msg":""}
        if resp.status_code == 403:
            return {"status":"error","error_msg":"Invalid API key or quota exceeded"}
        if resp.status_code != 200:
            return {"status":"error","error_msg":f"HTTP {resp.status_code}"}
        data  = resp.json()
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        und   = stats.get("undetected", 0)
        har   = stats.get("harmless", 0)
        total = mal + sus + und + har
        if mal >= 3:   status = "malicious"
        elif mal > 0 or sus > 0: status = "suspicious"
        else:          status = "clean"
        return {"status":status,"malicious":mal,"suspicious":sus,
                "undetected":und,"total":total,"score":f"{mal}/{total}","error_msg":""}
    except requests.exceptions.ConnectionError:
        return {"status":"error","error_msg":"No internet connection"}
    except requests.exceptions.Timeout:
        return {"status":"error","error_msg":"Request timed out"}
    except Exception as e:
        return {"status":"error","error_msg":str(e)}

def vt_check_added_files(added_files, progress_cb=None):
    results = []
    total = len(added_files)
    for i, f in enumerate(added_files):
        if progress_cb:
            progress_cb(i + 1, total, f["path"])
        vt = vt_check_hash(f["new_hash"])
        results.append({"path": f["path"], "hash": f["new_hash"], "vt": vt})
        if i < total - 1:
            time.sleep(15)
    return results

# ══════════════════════ DATABASE ══════════════════════

class BaselineDB:
    def __init__(self):
        self.path = "baseline.db"
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS drives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                drive_path TEXT UNIQUE NOT NULL,
                total_files INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_scan TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                drive_path TEXT NOT NULL, rel_path TEXT NOT NULL,
                sha256 TEXT NOT NULL, file_size INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(drive_path, rel_path))""")
            c.commit()

    def has_baseline(self, drive):
        with sqlite3.connect(self.path) as c:
            a = c.execute("SELECT 1 FROM drives WHERE drive_path=?",(drive,)).fetchone() is not None
            b = c.execute("SELECT 1 FROM baseline WHERE drive_path=? LIMIT 1",(drive,)).fetchone() is not None
        return a and b

    def save_baseline(self, drive, hashes):
        now = datetime.now().isoformat()
        with sqlite3.connect(self.path) as c:
            c.execute("DELETE FROM baseline WHERE drive_path=?",(drive,))
            c.execute("INSERT OR REPLACE INTO drives VALUES(NULL,?,?,?,NULL)",(drive,len(hashes),now))
            c.executemany("INSERT INTO baseline VALUES(NULL,?,?,?,?,?)",
                [(drive,p,v["hash"],v["size"],now) for p,v in hashes.items()])
            c.commit()

    def get_baseline(self, drive):
        with sqlite3.connect(self.path) as c:
            rows = c.execute("SELECT rel_path,sha256,file_size FROM baseline WHERE drive_path=?",(drive,)).fetchall()
        return {r[0]:{"hash":r[1],"size":r[2]} for r in rows}

    def update_last_scan(self, drive):
        with sqlite3.connect(self.path) as c:
            c.execute("UPDATE drives SET last_scan=? WHERE drive_path=?",(datetime.now().isoformat(),drive))
            c.commit()

    def delete_baseline(self, drive):
        with sqlite3.connect(self.path) as c:
            c.execute("DELETE FROM baseline WHERE drive_path=?",(drive,))
            c.execute("DELETE FROM drives WHERE drive_path=?",(drive,))
            c.commit()

    def list_all(self):
        with sqlite3.connect(self.path) as c:
            return c.execute("SELECT drive_path,total_files,created_at FROM drives ORDER BY created_at DESC").fetchall()


class ScanDB:
    def __init__(self):
        self.path = "scan_history.db"
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as c:
            try:
                cols = [r[1] for r in c.execute("PRAGMA table_info(scans)").fetchall()]
                if cols and "trigger" not in cols:
                    c.execute("ALTER TABLE scans ADD COLUMN trigger TEXT NOT NULL DEFAULT 'legacy'")
                    c.commit()
                if cols and "session_id" not in cols:
                    c.execute("ALTER TABLE scans ADD COLUMN session_id INTEGER DEFAULT 0")
                    c.commit()
            except: pass
            c.execute("""CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER DEFAULT 0,
                drive_path TEXT NOT NULL, scan_time TEXT NOT NULL,
                trigger TEXT NOT NULL DEFAULT 'manual',
                total_files INTEGER DEFAULT 0, modified INTEGER DEFAULT 0,
                added INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
                status TEXT NOT NULL)""")
            c.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL, event_type TEXT NOT NULL,
                rel_path TEXT NOT NULL, old_hash TEXT, new_hash TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id))""")
            c.commit()

    def save_scan(self, drive, results, trigger, session_id):
        now = datetime.now().isoformat()
        m=len(results["modified"]); a=len(results["added"]); d=len(results["deleted"])
        r=len(results.get("renamed",[]))
        if (m+a+d+r)==0:          status="CLEAN"
        elif (m+a+d)==0 and r>0:  status="WARNING"
        else:                      status="COMPROMISED"
        with sqlite3.connect(self.path) as c:
            cols = [r2[1] for r2 in c.execute("PRAGMA table_info(scans)").fetchall()]
            if "session_id" in cols:
                cur = c.execute(
                    "INSERT INTO scans(session_id,drive_path,scan_time,trigger,total_files,modified,added,deleted,status) VALUES(?,?,?,?,?,?,?,?,?)",
                    (session_id,drive,now,trigger,results["total"],m,a,d,status))
            else:
                cur = c.execute(
                    "INSERT INTO scans(drive_path,scan_time,trigger,total_files,modified,added,deleted,status) VALUES(?,?,?,?,?,?,?,?)",
                    (drive,now,trigger,results["total"],m,a,d,status))
            sid = cur.lastrowid
            rows=[]
            for x in results["modified"]: rows.append((sid,"MODIFIED",x["path"],x["old_hash"],x["new_hash"]))
            for x in results["added"]:    rows.append((sid,"ADDED",x["path"],None,x["new_hash"]))
            for x in results["deleted"]:  rows.append((sid,"DELETED",x["path"],x["old_hash"],None))
            for x in results.get("renamed",[]):
                rows.append((sid,"RENAMED",x["new_path"],x["hash"],x["hash"]))
            c.executemany("INSERT INTO events VALUES(NULL,?,?,?,?,?)",rows)
            c.commit()
        return sid

    def get_history(self, limit=100):
        with sqlite3.connect(self.path) as c:
            cols = [r[1] for r in c.execute("PRAGMA table_info(scans)").fetchall()]
            if "session_id" in cols:
                return c.execute(
                    "SELECT id,session_id,drive_path,scan_time,trigger,total_files,modified,added,deleted,status FROM scans ORDER BY id DESC LIMIT ?",
                    (limit,)).fetchall()
            else:
                return c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()

    def clear_history(self):
        with sqlite3.connect(self.path) as c:
            c.execute("DELETE FROM events")
            c.execute("DELETE FROM scans")
            c.commit()

# ══════════════════════ HASHING ══════════════════════

# ── Hidden / system file detection ─────────────────────────────────────────
# Always-skip directory names (names that start with '$' are also skipped)
_SKIP_DIRS = {"System Volume Information", "$RECYCLE.BIN", "RECYCLER",
              "FOUND.000", ".Trash-1000"}

def _is_hidden_or_system(path):
    """
    Returns True if the file/directory should be invisible to the user:
      • On Windows: checks the HIDDEN and SYSTEM attribute flags via os.stat.
        This catches desktop.ini, Thumbs.db, autorun.inf, etc. regardless of
        name casing, and any other file Windows marks hidden/system.
      • On other OSes: treats dot-files as hidden.
    """
    try:
        if sys.platform == "win32":
            attrs = os.stat(path).st_file_attributes
            return bool(attrs & (_stat_mod.FILE_ATTRIBUTE_HIDDEN |
                                  _stat_mod.FILE_ATTRIBUTE_SYSTEM))
        else:
            return os.path.basename(path).startswith('.')
    except:
        return False

def hash_file(path):
    sha = hashlib.sha256()
    try:
        with open(path,"rb") as f:
            while chunk := f.read(65536): sha.update(chunk)
        return sha.hexdigest()
    except: return "UNREADABLE"

def scan_drive(drive, progress_cb=None):
    results, all_files = {}, []
    for root, dirs, files in os.walk(drive):
        # Remove system/hidden dirs in-place so os.walk won't descend into them
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS
            and not d.startswith('$')
            and not _is_hidden_or_system(os.path.join(root, d))
        ]
        for fname in files:
            fpath = os.path.join(root, fname)
            # Skip any hidden or system file (covers desktop.ini, Thumbs.db, etc.)
            if fname.startswith('$') or _is_hidden_or_system(fpath):
                continue
            all_files.append(fpath)
    total = len(all_files)
    for i,fpath in enumerate(all_files):
        rel = os.path.relpath(fpath, drive)
        try: size = os.path.getsize(fpath)
        except: size = 0
        results[rel] = {"hash": hash_file(fpath), "size": size}
        if progress_cb: progress_cb(i+1, total, rel)
    return results

def compare(baseline, current):
    modified = []
    added = []
    deleted = []
    renamed = []   # NEW

    # Step 1: Normal detection
    for path, info in current.items():
        if path in baseline:
            if info["hash"] != baseline[path]["hash"]:
                modified.append({
                    "path": path,
                    "old_hash": baseline[path]["hash"],
                    "new_hash": info["hash"]
                })
        else:
            added.append({
                "path": path,
                "new_hash": info["hash"]
            })

    for path, info in baseline.items():
        if path not in current:
            deleted.append({
                "path": path,
                "old_hash": info["hash"]
            })

    # Step 2: Detect rename/move using hash matching
    added_copy = added.copy()
    deleted_copy = deleted.copy()

    for d in deleted_copy:
        for a in list(added):
            if d["old_hash"] == a["new_hash"]:
                old_dir = os.path.normcase(os.path.normpath(os.path.dirname(d["path"])))
                new_dir = os.path.normcase(os.path.normpath(os.path.dirname(a["path"])))
                ev_type = "renamed" if old_dir == new_dir else "moved"
                renamed.append({
                    "old_path":   d["path"],
                    "new_path":   a["path"],
                    "hash":       d["old_hash"],
                    "event_type": ev_type
                })
                added.remove(a)
                deleted.remove(d)
                break

    return {
        "total": len(current),
        "modified": modified,
        "added": added,
        "deleted": deleted,
        "renamed": renamed
    }

# ══════════════════════ WINDOWS ══════════════════════

def get_removable_drives():
    drives=[]
    if sys.platform!="win32": return drives
    try:
        import ctypes
        bitmask=ctypes.windll.kernel32.GetLogicalDrives()
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if bitmask&1:
                drive=f"{letter}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(drive)==2: drives.append(drive)
            bitmask>>=1
    except: pass
    return drives

def get_explorer_drive_windows():
    open_drives=set()
    if not WIN32_AVAILABLE: return open_drives
    try:
        shell=win32com.client.Dispatch("Shell.Application")
        for window in shell.Windows():
            try:
                url=window.LocationURL
                if url and url.startswith("file:///"):
                    path=url.replace("file:///","").replace("/","\\")
                    drive=os.path.splitdrive(path)[0]+"\\"
                    if drive and len(drive)==3: open_drives.add(drive.upper())
            except: pass
    except: pass
    return open_drives

def send_notification(title,message):
    if PLYER_AVAILABLE:
        try: notification.notify(title=title,message=message,app_name="File Integrity Checker",timeout=6)
        except: pass

# ══════════════════════ PDF REPORT ══════════════════════

# Common Unicode → ASCII replacements for latin-1 PDF fonts
_PDF_UNICODE_MAP = {
    '\u2014': '--',   # em-dash  —
    '\u2013': '-',    # en-dash  –
    '\u2012': '-',    # figure dash
    '\u2018': "'",    # left single quote  '
    '\u2019': "'",    # right single quote  '
    '\u201c': '"',    # left double quote  "
    '\u201d': '"',    # right double quote  "
    '\u2022': '*',    # bullet  •
    '\u2026': '...',  # ellipsis  …
    '\u2192': '->',   # right arrow  →
    '\u00d7': 'x',    # multiplication  ×
    '\u00b7': '.',    # middle dot  ·
    '\u2610': '[ ]',  # ballot box
    '\u2611': '[x]',  # ballot box checked
    '\u2714': 'OK',   # heavy check mark  ✔
    '\u26a0': '!',    # warning sign  ⚠
    '\u274c': 'X',    # cross mark  ❌
}

def _safe_str(text, maxlen=90):
    """Sanitise text for fpdf latin-1 fonts: replace known Unicode chars then
    strip anything else outside latin-1, and trim to maxlen characters."""
    t = str(text)
    for uc, asc in _PDF_UNICODE_MAP.items():
        t = t.replace(uc, asc)
    if len(t) > maxlen:
        t = t[:maxlen-3] + '...'
    # Replace any remaining non-latin-1 character with '?'
    return t.encode('latin-1', errors='replace').decode('latin-1')

def _pdf_header(pdf, title_extra=""):
    pdf.set_fill_color(30,58,95); pdf.rect(0,0,210,28,'F')
    pdf.set_font("Helvetica","B",15); pdf.set_text_color(255,255,255)
    pdf.set_xy(0,7)
    title = "FILE INTEGRITY CHECKER  -  SCAN REPORT"
    if title_extra:
        title += f"  {title_extra}"
    pdf.cell(210,12,title,align="C")
    pdf.set_fill_color(219,234,254); pdf.rect(0,28,210,10,'F')
    pdf.set_font("Helvetica","",9); pdf.set_text_color(45,90,142)
    pdf.set_xy(0,30)
    pdf.cell(210,6,"SHA-256  |  SQLite  |  Python  |  VirusTotal  |  File Integrity Checker",align="C")
    pdf.set_text_color(0,0,0); pdf.set_xy(10,46)

def _pdf_section_divider(pdf, text, fill_rgb=(30,58,95), text_rgb=(255,255,255)):
    pdf.set_font("Helvetica","B",11)
    pdf.set_fill_color(*fill_rgb); pdf.set_text_color(*text_rgb)
    # Always sanitise through _safe_str so no Unicode slips through
    pdf.cell(190,8,f"  {_safe_str(text, 85)}",fill=True,ln=True)
    pdf.set_text_color(0,0,0); pdf.ln(2)

def _pdf_render_one_scan(pdf, drive, results, session_id, timestamp, trigger, vt_results, sec_idx, total_secs):
    m = len(results["modified"])
    a = len(results["added"])
    d = len(results["deleted"])
    rn = len(results.get("renamed", []))
    total = results["total"]
    clean = (m + a + d + rn) == 0

    extra = f"({sec_idx+1}/{total_secs})" if total_secs > 1 else ""
    _pdf_header(pdf, extra)

    # ── SCAN INFO ──
    _pdf_section_divider(pdf, "Scan Information")
    for label,value in [
        ("Session Scan ID", f"S#{session_id}"),
        ("Date and Time",   timestamp),
        ("Path Scanned",    _safe_str(drive, 70)),
        ("Trigger",         _safe_str(trigger, 40)),
        ("Total Files",     str(total))
    ]:
        pdf.set_font("Helvetica","B",10); pdf.set_fill_color(235,244,255)
        pdf.cell(45,7,f"  {label}",fill=True,border=1)
        pdf.set_font("Helvetica","",10); pdf.set_fill_color(255,255,255)
        pdf.cell(145,7,f"  {_safe_str(value,70)}",fill=True,border=1,ln=True)
    pdf.ln(3)

    # ── RESULT BADGE ──
    if clean:
        pdf.set_fill_color(5,150,105)
    else:
        pdf.set_fill_color(220,38,38)
    pdf.set_text_color(255,255,255); pdf.set_font("Helvetica","B",13)
    pdf.cell(190,12,
        "INTEGRITY VERIFIED  -  ALL FILES MATCH BASELINE" if clean else "INTEGRITY COMPROMISED  -  CHANGES DETECTED",
        fill=True,align="C",ln=True)
    pdf.set_text_color(0,0,0); pdf.ln(4)

    # ── SUMMARY CARDS ──
    cw=47; pdf.set_font("Helvetica","B",10)
    for lbl,fc in [("TOTAL FILES",(219,234,254)),("MODIFIED",(254,243,199)),
                   ("ADDED",(209,250,229)),("DELETED",(254,226,226)),("RENAMED",(237,233,254))]:
        pdf.set_fill_color(*fc); pdf.cell(cw,6,lbl,fill=True,border=1,align="C")
    pdf.ln(); pdf.set_font("Helvetica","B",18)
    for val,fc,tc in [(total,(235,244,255),(29,78,216)),(m,(255,251,235),(217,119,6)),
                      (a,(236,253,245),(5,150,105)),(d,(254,242,242),(220,38,38)),
                      (rn,(245,243,255),(109,40,217))]:
        pdf.set_fill_color(*fc); pdf.set_text_color(*tc)
        pdf.cell(cw,12,str(val),fill=True,border=1,align="C")
    pdf.set_text_color(0,0,0); pdf.ln(); pdf.ln(6)

    # ── MODIFIED FILES ──
    if results["modified"]:
        _pdf_section_divider(pdf, f"Modified Files  ({m})", (180,100,0), (255,255,255))
        for x in results["modified"]:
            pdf.set_font("Helvetica","B",10); pdf.set_fill_color(255,253,245)
            pdf.cell(190,6,f"  {_safe_str(x['path'],80)}",fill=True,border="B",ln=True)
            pdf.set_font("Courier","",8); pdf.set_text_color(100,100,100)
            pdf.cell(20,5,"  OLD HASH:",ln=False); pdf.cell(170,5,_safe_str(x['old_hash'],70),ln=True)
            pdf.cell(20,5,"  NEW HASH:",ln=False); pdf.cell(170,5,_safe_str(x['new_hash'],70),ln=True)
            pdf.set_text_color(0,0,0); pdf.ln(1)
        pdf.ln(3)

    # ── RENAMED / MOVED FILES ──
    renamed = results.get("renamed", [])
    rn = len(renamed)
    if renamed:
        _pdf_section_divider(pdf, f"Renamed / Moved Files  ({rn})  — same content, path changed",
                             (90, 50, 160), (255,255,255))
        for x in renamed:
            pdf.set_font("Helvetica","B",10); pdf.set_fill_color(245,240,255)
            pdf.cell(190,6,f"  {_safe_str(x['new_path'],80)}",fill=True,border="B",ln=True)
            pdf.set_font("Courier","",8); pdf.set_text_color(100,100,100)
            pdf.cell(25,5,"  FROM:", ln=False); pdf.cell(165,5,_safe_str(x['old_path'],70),ln=True)
            pdf.cell(25,5,"  TO  :", ln=False); pdf.cell(165,5,_safe_str(x['new_path'],70),ln=True)
            pdf.cell(25,5,"  HASH:", ln=False); pdf.cell(165,5,_safe_str(x['hash'],70),ln=True)
            pdf.set_text_color(0,0,0); pdf.ln(1)
        pdf.ln(3)

    # ── ADDED FILES with VirusTotal ──
    if results["added"]:
        vt_lookup = {vr["path"]:vr["vt"] for vr in vt_results} if vt_results else {}
        hdr_txt = f"Added Files  ({a})  -  VirusTotal Results" if vt_results else f"Added Files  ({a})"
        _pdf_section_divider(pdf, hdr_txt, (5,100,60), (255,255,255))
        for x in results["added"]:
            pdf.set_font("Helvetica","B",10); pdf.set_fill_color(245,255,250)
            pdf.cell(190,6,f"  {_safe_str(x['path'],80)}",fill=True,border="B",ln=True)
            pdf.set_font("Courier","",8); pdf.set_text_color(100,100,100)
            pdf.cell(20,5,"  SHA-256:",ln=False)
            pdf.cell(170,5,_safe_str(x['new_hash'],70),ln=True)
            pdf.set_text_color(0,0,0)

            # VirusTotal block
            vt = vt_lookup.get(x["path"])
            if vt:
                s = vt.get("status","")
                if s=="malicious":
                    pdf.set_fill_color(254,226,226); pdf.set_text_color(180,30,30)
                    badge = f"MALICIOUS  -  {vt.get('score','?')} engines flagged"
                elif s=="suspicious":
                    pdf.set_fill_color(255,237,213); pdf.set_text_color(180,90,10)
                    badge = f"SUSPICIOUS  -  {vt.get('score','?')} engines flagged"
                elif s=="clean":
                    pdf.set_fill_color(209,250,229); pdf.set_text_color(5,120,70)
                    badge = f"CLEAN  -  0/{vt.get('total','?')} engines"
                elif s=="unknown":
                    pdf.set_fill_color(243,244,246); pdf.set_text_color(80,80,80)
                    badge = "NOT IN DATABASE  -  Unknown file"
                else:
                    pdf.set_fill_color(243,244,246); pdf.set_text_color(120,50,50)
                    badge = f"ERROR  -  {_safe_str(vt.get('error_msg',''),50)}"
                pdf.set_font("Helvetica","B",9)
                pdf.cell(190,6,f"  VirusTotal:  {badge}",fill=True,ln=True)
                if vt.get("total",0) > 0 and s not in ("unknown","error"):
                    pdf.set_font("Helvetica","",8); pdf.set_text_color(80,80,80)
                    pdf.set_fill_color(250,250,252)
                    score_line = (f"  Score: {vt.get('malicious',0)} malicious | "
                                  f"{vt.get('suspicious',0)} suspicious | "
                                  f"{vt.get('undetected',0)} undetected | "
                                  f"Total engines: {vt.get('total',0)}")
                    pdf.cell(190,5,score_line,fill=True,ln=True)
                pdf.set_text_color(0,0,0)
            else:
                pdf.set_font("Helvetica","I",8); pdf.set_fill_color(243,244,246)
                pdf.set_text_color(120,120,120)
                pdf.cell(190,5,"  VirusTotal: Not checked (click Check VirusTotal button first)",fill=True,ln=True)
                pdf.set_text_color(0,0,0)
            pdf.ln(2)
        pdf.ln(3)

    # ── DELETED FILES ──
    if results["deleted"]:
        _pdf_section_divider(pdf, f"Deleted Files  ({d})", (150,30,30), (255,255,255))
        for x in results["deleted"]:
            pdf.set_font("Helvetica","B",10); pdf.set_fill_color(255,248,248)
            pdf.cell(190,6,f"  {_safe_str(x['path'],80)}",fill=True,border="B",ln=True)
            pdf.set_font("Courier","",8); pdf.set_text_color(100,100,100)
            pdf.cell(20,5,"  SHA-256:",ln=False)
            pdf.cell(170,5,_safe_str(x['old_hash'],70),ln=True)
            pdf.set_text_color(0,0,0); pdf.ln(1)
        pdf.ln(3)

    # ── CLEAN MESSAGE ──
    if clean:
        pdf.set_font("Helvetica","B",12); pdf.set_fill_color(236,253,245); pdf.set_text_color(5,150,105)
        pdf.cell(190,12,"All files match the baseline exactly. Integrity VERIFIED.",
                 fill=True,align="C",border=1,ln=True)
        pdf.set_text_color(0,0,0)

    # ── FOOTER ──
    pdf.ln(6)
    pdf.set_draw_color(30,58,95); pdf.set_line_width(0.5)
    pdf.line(10,pdf.get_y(),200,pdf.get_y()); pdf.ln(3)
    pdf.set_font("Helvetica","I",8); pdf.set_text_color(100,100,100)
    pdf.cell(190,5,
        f"Generated by File Integrity Checker  |  {_safe_str(timestamp,30)}  |  SHA-256  |  VirusTotal API",
        align="C",ln=True)


def generate_pdf_report(drive, results, session_id, timestamp, trigger,
                        vt_results=None, extra_sections=None):
    """
    Generates and saves PDF report.
    extra_sections = list of dicts for additional scans done this session.
    """
    if not FPDF_AVAILABLE:
        messagebox.showerror("Library Missing",
            "fpdf2 is not installed.\n\nRun:  pip install fpdf2\n\nThen restart the app.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files","*.pdf")],
        initialfile=f"ScanReport_S{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        title="Save Scan Report"
    )
    if not file_path:
        return  # user cancelled

    # Build sections list
    sections = [{"drive":drive,"results":results,"session_id":session_id,
                 "timestamp":timestamp,"trigger":trigger,"vt":vt_results}]
    if extra_sections:
        sections.extend(extra_sections)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    total_secs = len(sections)

    for idx, sec in enumerate(sections):
        pdf.add_page()
        _pdf_render_one_scan(
            pdf,
            sec["drive"], sec["results"], sec["session_id"],
            sec["timestamp"], sec["trigger"], sec.get("vt"),
            idx, total_secs
        )

    # ── WRITE PDF TO DISK ──
    # fpdf2 >= 2.5 : pdf.output() returns bytes (no arguments)
    # fpdf2 <  2.5 : pdf.output(name) writes to file and returns None
    # We handle both by always capturing the return value and writing manually.
    try:
        raw = pdf.output()          # returns bytes in modern fpdf2
        if raw is None:
            # Old fpdf2: file was already written to `name` arg — but we didn't
            # pass one, so try again with the path
            pdf.output(file_path)
        else:
            if isinstance(raw, str):
                raw = raw.encode('latin-1')
            with open(file_path, 'wb') as f:
                f.write(raw)

        # Verify the file actually exists and has content
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            messagebox.showerror("Save Failed",
                f"File was not written to disk.\n\nPath: {file_path}\n\nPlease check folder permissions.")
            return

        messagebox.showinfo("Report Saved",
            f"Report saved successfully!\n\n"
            f"File:     {os.path.basename(file_path)}\n"
            f"Location: {os.path.dirname(file_path)}\n"
            f"Size:     {os.path.getsize(file_path):,} bytes")

    except Exception as e:
        messagebox.showerror("Save Failed",
            f"Could not save PDF report.\n\nError: {e}\n\n"
            f"Make sure fpdf2 is installed:\n  pip install fpdf2")


# ══════════════════════ WIDGETS ══════════════════════

class StatCard(ctk.CTkFrame):
    def __init__(self,parent,icon,label,value="—",color=None,**kwargs):
        if color is None: color=C["cyan"]
        kwargs.setdefault("fg_color",C["card"]); kwargs.setdefault("corner_radius",14)
        super().__init__(parent,**kwargs)
        ctk.CTkFrame(self,height=4,corner_radius=2,fg_color=color).pack(fill="x")
        inner=ctk.CTkFrame(self,fg_color="transparent")
        inner.pack(fill="both",expand=True,padx=18,pady=14)
        top=ctk.CTkFrame(inner,fg_color="transparent"); top.pack(fill="x")
        ctk.CTkLabel(top,text=icon,font=(FONT_UI,22)).pack(side="left")
        self.val_label=ctk.CTkLabel(inner,text=value,font=(FONT_UI,38,"bold"),text_color=color)
        self.val_label.pack(anchor="w",pady=(4,0))
        ctk.CTkLabel(inner,text=label,font=(FONT_UI,12),text_color=C["t2"]).pack(anchor="w")
    def set_value(self,v): self.val_label.configure(text=str(v))


class LogBox(ctk.CTkTextbox):
    def __init__(self,parent,**kwargs):
        kwargs.setdefault("fg_color",C["card"])
        kwargs.setdefault("font",(FONT_MONO,14))
        kwargs.setdefault("corner_radius",10); kwargs.setdefault("border_width",1)
        kwargs.setdefault("border_color",C["border"]); kwargs.setdefault("wrap","word")
        super().__init__(parent,**kwargs)
        self.configure(state="disabled")
        self.tag_config("info",foreground="#2D5A8E")
        self.tag_config("success",foreground="#059669")
        self.tag_config("warn",foreground="#D97706")
        self.tag_config("error",foreground="#DC2626")
        self.tag_config("cyan",foreground="#1D4ED8")
        self.tag_config("muted",foreground="#4A7BA7")
        self.tag_config("ts",foreground="#93C5FD")

    def append(self,msg,tag="info"):
        self.configure(state="normal")
        ts=datetime.now().strftime("%H:%M:%S")
        self.insert("end",f"  {ts}   ","ts")
        self.insert("end",f"{msg}\n",tag)
        self.see("end"); self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal"); self.delete("1.0","end"); self.configure(state="disabled")


class ResultsBox(ctk.CTkTextbox):
    """Textbox with colour tags for VT status lines."""
    def __init__(self,parent,**kwargs):
        kwargs.setdefault("fg_color",C["card"])
        kwargs.setdefault("font",(FONT_MONO,14))
        kwargs.setdefault("corner_radius",12)
        kwargs.setdefault("border_width",1)
        kwargs.setdefault("border_color",C["border"])
        kwargs.setdefault("wrap","word")
        super().__init__(parent,**kwargs)
        self.configure(state="disabled")
        self.tag_config("vt_mal",   foreground="#DC2626")
        self.tag_config("vt_sus",   foreground="#EA580C")
        self.tag_config("vt_clean", foreground="#059669")
        self.tag_config("vt_unk",   foreground="#D97706")
        self.tag_config("vt_err",   foreground="#6B7280")
        self.tag_config("vt_score", foreground="#4A7BA7")
        self.tag_config("header",   foreground="#1D4ED8")
        self.tag_config("normal",   foreground="#1E3A5F")
        self.tag_config("muted",    foreground="#4A7BA7")

    def write(self, text, tag="normal"):
        self.configure(state="normal")
        self.insert("end", text, tag)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal"); self.delete("1.0","end"); self.configure(state="disabled")


# ══════════════════════ APP ══════════════════════

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker")
        self.geometry("1340x840"); self.minsize(1100,700)
        self.configure(fg_color=C["bg0"])
        self.protocol("WM_DELETE_WINDOW",self._on_close)
        self.baseline_db=BaselineDB(); self.scan_db=ScanDB()
        self._known_drives=set(); self._explorer_open={}
        self._scanning=False; self._baseline_creating=False; self._folder_scanning=False
        self._vt_running=False
        self._monitoring_active=False
        self._stop_event=threading.Event(); self._ui_queue=queue.Queue()
        self._selected_drive=None; self._folder_path=""; self._scan_folder_path=""

        self._last_results=None; self._last_drive=None
        self._last_session_id=None; self._last_timestamp=None; self._last_trigger=None
        self._last_vt_results=None
        self._session_scans=[]   # all scans this session

        self._build_ui()
        self._refresh_history(); self._refresh_profiles()
        threading.Thread(target=self._monitor_loop,daemon=True).start()
        self._process_queue()

    # ── UI BUILD ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        sb=ctk.CTkFrame(self,width=260,corner_radius=0,fg_color=C["bg1"])
        sb.pack(side="left",fill="y"); sb.pack_propagate(False)

        logo=ctk.CTkFrame(sb,fg_color=C["card2"],corner_radius=0); logo.pack(fill="x")
        li=ctk.CTkFrame(logo,fg_color="transparent"); li.pack(padx=16,pady=18)
        ir=ctk.CTkFrame(li,fg_color="transparent"); ir.pack(anchor="w")
        sbg=ctk.CTkFrame(ir,fg_color=C["cyan"],corner_radius=10,width=46,height=46)
        sbg.pack(side="left",padx=(0,10)); sbg.pack_propagate(False)
        ctk.CTkLabel(sbg,text="🛡",font=(FONT_UI,22),text_color="#FFFFFF").pack(expand=True)
        tc=ctk.CTkFrame(ir,fg_color="transparent"); tc.pack(side="left")
        ctk.CTkLabel(tc,text="File Integrity",font=(FONT_UI,14,"bold"),text_color=C["t0"]).pack(anchor="w")
        ctk.CTkLabel(tc,text="Checker",font=(FONT_UI,12),text_color=C["cyan"]).pack(anchor="w")
        ctk.CTkFrame(li,height=1,fg_color=C["border"]).pack(fill="x",pady=(10,8))
        ctk.CTkLabel(li,text="SHA-256  ·  SQLite  ·  VirusTotal",font=(FONT_UI,9),text_color=C["t2"]).pack(anchor="w")

        self._sb_section(sb,"CONNECTED DRIVES")
        self.drives_frame=ctk.CTkScrollableFrame(sb,height=80,fg_color=C["bg0"],
            corner_radius=8,border_width=1,border_color=C["border"])
        self.drives_frame.pack(fill="x",padx=12,pady=(0,4))
        self._render_no_drives()
        self._sb_divider(sb)

        self._sb_section(sb,"PROGRESS")
        self.prog_label=ctk.CTkLabel(sb,text="Idle",font=(FONT_MONO,11),text_color=C["t2"],
            wraplength=228,justify="left")
        self.prog_label.pack(anchor="w",padx=16,pady=(4,4))
        self.prog_bar=ctk.CTkProgressBar(sb,height=8,progress_color=C["cyan"],
            fg_color=C["border"],corner_radius=4)
        self.prog_bar.pack(fill="x",padx=16,pady=(0,4)); self.prog_bar.set(0)
        self.prog_pct=ctk.CTkLabel(sb,text="",font=(FONT_UI,10),text_color=C["t2"])
        self.prog_pct.pack(anchor="w",padx=16)
        self._sb_divider(sb)

        btn_frame=ctk.CTkFrame(sb,fg_color="transparent")
        btn_frame.pack(side="bottom",fill="x",padx=12,pady=(0,12))

        self.start_mon_btn=ctk.CTkButton(btn_frame,text="▶  START MONITORING",
            fg_color=C["green"],hover_color="#047857",text_color="#FFFFFF",
            font=(FONT_UI,12,"bold"),height=38,corner_radius=10,command=self._toggle_monitoring)
        self.start_mon_btn.pack(fill="x",pady=(0,6))
        ctk.CTkButton(btn_frame,text="📦  CREATE BASELINE",fg_color=C["purple"],hover_color="#6D28D9",
            text_color="#FFFFFF",font=(FONT_UI,12,"bold"),height=38,corner_radius=10,
            command=self._create_usb_baseline).pack(fill="x",pady=(0,6))
        ctk.CTkButton(btn_frame,text="⚡  RUN MANUAL SCAN",fg_color=C["cyan"],hover_color=C["cyan_dim"],
            text_color="#FFFFFF",font=(FONT_UI,12,"bold"),height=38,corner_radius=10,
            command=self._manual_scan).pack(fill="x",pady=(0,6))
        ctk.CTkButton(btn_frame,text="🔄  UPDATE BASELINE",fg_color=C["gold_dim"],hover_color=C["gold"],
            text_color="#FFFFFF",font=(FONT_UI,12,"bold"),height=38,corner_radius=10,
            command=self._update_usb_baseline).pack(fill="x",pady=(0,6))
        ctk.CTkButton(btn_frame,text="🗑  DELETE BASELINE",fg_color=C["red"],hover_color="#B91C1C",
            text_color="#FFFFFF",font=(FONT_UI,12,"bold"),height=38,corner_radius=10,
            command=self._delete_usb_baseline).pack(fill="x")

        main=ctk.CTkFrame(self,fg_color=C["bg0"]); main.pack(side="left",fill="both",expand=True)
        hbar=ctk.CTkFrame(main,fg_color=C["bg1"],corner_radius=0,height=58); hbar.pack(fill="x")
        hbar.pack_propagate(False)
        ctk.CTkLabel(hbar,text="INTEGRITY MONITOR DASHBOARD",
            font=(FONT_UI,14,"bold"),text_color=C["t0"]).pack(side="left",padx=24,pady=16)
        self.clock_label=ctk.CTkLabel(hbar,text="",font=(FONT_MONO,13),text_color=C["t2"])
        self.clock_label.pack(side="right",padx=24); self._tick_clock()

        ta=ctk.CTkFrame(main,fg_color=C["bg0"]); ta.pack(fill="both",expand=True,padx=20,pady=16)
        self.tabs=ctk.CTkTabview(ta,fg_color=C["bg2"],
            segmented_button_fg_color=C["bg1"],segmented_button_selected_color=C["cyan"],
            segmented_button_selected_hover_color=C["cyan_dim"],
            segmented_button_unselected_color=C["bg1"],segmented_button_unselected_hover_color=C["hover"],
            text_color=C["t0"],text_color_disabled=C["t2"],
            border_width=1,border_color=C["border"],corner_radius=14)
        self.tabs.pack(fill="both",expand=True)
        self.tabs.add("  🖥  USB Monitor  ")
        self.tabs.add("  📁  File Integrity  ")
        self.tabs.add("  🔍  Last Scan  ")
        self.tabs.add("  📋  History  ")
        self._build_usb_tab(); self._build_folder_tab()
        self._build_scan_tab(); self._build_history_tab()

    def _sb_section(self,parent,title):
        ctk.CTkLabel(parent,text=title,font=(FONT_UI,9,"bold"),text_color=C["t2"]).pack(anchor="w",padx=16,pady=(8,2))

    def _sb_divider(self,parent):
        ctk.CTkFrame(parent,height=1,fg_color=C["border"]).pack(fill="x",padx=12,pady=10)

    def _tick_clock(self):
        self.clock_label.configure(text=datetime.now().strftime("%A  %d %b %Y   %H:%M:%S"))
        self.after(1000,self._tick_clock)

    def _toggle_monitoring(self):
        if not self._monitoring_active:
            self._monitoring_active=True
            self.start_mon_btn.configure(text="⏹  STOP MONITORING",fg_color=C["red"],hover_color="#B91C1C")
            self.log.append("USB monitoring started","cyan")
        else:
            self._monitoring_active=False
            self.start_mon_btn.configure(text="▶  START MONITORING",fg_color=C["green"],hover_color="#047857")
            self.log.append("USB monitoring stopped","warn")

    # ── USB MONITOR TAB ───────────────────────────────────────────────────────

    def _build_usb_tab(self):
        tab=self.tabs.tab("  🖥  USB Monitor  "); tab.configure(fg_color="transparent")
        row=ctk.CTkFrame(tab,fg_color="transparent"); row.pack(fill="x",pady=(4,14))
        self._cards={}
        for i,(k,icon,label,color) in enumerate([
            ("files","📄","Total Files",C["cyan"]),("modified","✏️","Modified",C["yellow"]),
            ("added","➕","Added",C["green"]),("deleted","🗑","Deleted",C["red"]),
        ]):
            card=StatCard(row,icon=icon,label=label,color=color)
            card.grid(row=0,column=i,padx=(0,10) if i<3 else 0,sticky="nsew")
            row.columnconfigure(i,weight=1); self._cards[k]=card
        lh=ctk.CTkFrame(tab,fg_color="transparent"); lh.pack(fill="x",pady=(0,6))
        ctk.CTkLabel(lh,text="ACTIVITY LOG",font=(FONT_UI,11,"bold"),text_color=C["t1"]).pack(side="left")
        ctk.CTkButton(lh,text="Clear Log",width=90,height=28,fg_color=C["card2"],
            hover_color=C["hover"],text_color=C["t1"],font=(FONT_UI,11),corner_radius=8,
            command=lambda:self.log.clear()).pack(side="right")
        self.log=LogBox(tab); self.log.pack(fill="both",expand=True)
        self.log.append("Press 'START MONITORING' to enable auto-baseline and auto-scan.","warn")

    # ── FOLDER INTEGRITY TAB ──────────────────────────────────────────────────

    def _build_folder_tab(self):
        tab=self.tabs.tab("  📁  File Integrity  "); tab.configure(fg_color="transparent")
        split=ctk.CTkFrame(tab,fg_color="transparent"); split.pack(fill="both",expand=True)
        split.columnconfigure(0,weight=1); split.columnconfigure(1,weight=1); split.rowconfigure(0,weight=1)
        left=ctk.CTkFrame(split,fg_color="transparent"); left.grid(row=0,column=0,sticky="nsew",padx=(0,10))
        right=ctk.CTkFrame(split,fg_color="transparent"); right.grid(row=0,column=1,sticky="nsew")

        bc=ctk.CTkFrame(left,fg_color=C["card"],corner_radius=12,border_width=1,border_color=C["border"]); bc.pack(fill="x",pady=(0,10))
        bh=ctk.CTkFrame(bc,fg_color=C["card2"],corner_radius=0,height=36); bh.pack(fill="x"); bh.pack_propagate(False)
        ctk.CTkLabel(bh,text="  ◆  CREATE BASELINE",font=(FONT_MONO,11,"bold"),text_color=C["cyan"]).pack(side="left",padx=12,pady=8)
        bb=ctk.CTkFrame(bc,fg_color="transparent"); bb.pack(fill="x",padx=14,pady=12)
        pr=ctk.CTkFrame(bb,fg_color="transparent"); pr.pack(fill="x",pady=(0,8))
        self.bl_path_label=ctk.CTkLabel(pr,text="No folder selected...",font=(FONT_MONO,11),text_color=C["t2"],anchor="w")
        self.bl_path_label.pack(side="left",fill="x",expand=True)
        ctk.CTkButton(pr,text="BROWSE",width=90,height=32,fg_color=C["card2"],border_width=1,
            border_color=C["border"],text_color=C["cyan"],hover_color=C["hover"],
            font=(FONT_MONO,11,"bold"),corner_radius=8,command=self._browse_baseline_folder).pack(side="right")
        nr=ctk.CTkFrame(bb,fg_color="transparent"); nr.pack(fill="x",pady=(0,10))
        ctk.CTkLabel(nr,text="Profile Name:",font=(FONT_UI,12),text_color=C["t1"],width=100).pack(side="left")
        self.profile_entry=ctk.CTkEntry(nr,font=(FONT_MONO,12),text_color=C["t0"],
            fg_color=C["bg2"],border_color=C["border"],border_width=1,corner_radius=8,height=34)
        self.profile_entry.pack(side="left",fill="x",expand=True,padx=(8,10))
        ctk.CTkButton(nr,text="GENERATE BASELINE",fg_color=C["cyan"],hover_color=C["cyan_dim"],
            text_color="#FFFFFF",font=(FONT_MONO,11,"bold"),height=34,corner_radius=8,
            command=self._generate_folder_baseline).pack(side="right")

        sc=ctk.CTkFrame(left,fg_color=C["card"],corner_radius=12,border_width=1,border_color=C["border"]); sc.pack(fill="x",pady=(0,10))
        sh=ctk.CTkFrame(sc,fg_color=C["card2"],corner_radius=0,height=36); sh.pack(fill="x"); sh.pack_propagate(False)
        ctk.CTkLabel(sh,text="  ◆  SCAN & COMPARE",font=(FONT_MONO,11,"bold"),text_color=C["cyan"]).pack(side="left",padx=12,pady=8)
        sb2=ctk.CTkFrame(sc,fg_color="transparent"); sb2.pack(fill="x",padx=14,pady=12)
        sr=ctk.CTkFrame(sb2,fg_color="transparent"); sr.pack(fill="x",pady=(0,8))
        ctk.CTkLabel(sr,text="Select Profile:",font=(FONT_UI,12),text_color=C["t1"],width=100).pack(side="left")
        self.profile_var=ctk.StringVar(value="— select profile —")
        self.profile_menu=ctk.CTkOptionMenu(sr,variable=self.profile_var,values=["— select profile —"],
            fg_color=C["bg2"],button_color=C["cyan"],button_hover_color=C["cyan_dim"],
            dropdown_fg_color=C["card"],text_color=C["t0"],font=(FONT_MONO,12),corner_radius=8,height=34,
            command=self._on_profile_selected)
        self.profile_menu.pack(side="left",fill="x",expand=True,padx=(8,0))
        spr=ctk.CTkFrame(sb2,fg_color="transparent"); spr.pack(fill="x",pady=(0,10))
        self.scan_path_label=ctk.CTkLabel(spr,text="No folder selected...",font=(FONT_MONO,11),text_color=C["t2"],anchor="w")
        self.scan_path_label.pack(side="left",fill="x",expand=True)
        ctk.CTkButton(spr,text="BROWSE",width=90,height=32,fg_color=C["card2"],border_width=1,
            border_color=C["border"],text_color=C["cyan"],hover_color=C["hover"],
            font=(FONT_MONO,11,"bold"),corner_radius=8,command=self._browse_scan_folder).pack(side="right")
        ctk.CTkButton(sb2,text="▶  START INTEGRITY SCAN",fg_color=C["green"],hover_color="#047857",
            text_color="#FFFFFF",font=(FONT_MONO,13,"bold"),height=42,corner_radius=8,
            command=self._start_folder_scan).pack(fill="x")

        fsr=ctk.CTkFrame(left,fg_color="transparent"); fsr.pack(fill="x",pady=(10,0))
        self._folder_cards={}
        for i,(k,label,color) in enumerate([("files","FILES SCANNED",C["cyan"]),("modified","MODIFIED",C["yellow"]),
                                            ("added","ADDED",C["green"]),("deleted","DELETED",C["red"])]):
            fc=ctk.CTkFrame(fsr,fg_color=C["card"],corner_radius=10,border_width=1,border_color=C["border"])
            fc.grid(row=0,column=i,padx=(0,8) if i<3 else 0,sticky="nsew"); fsr.columnconfigure(i,weight=1)
            ctk.CTkLabel(fc,text=label,font=(FONT_UI,9,"bold"),text_color=C["t2"]).pack(pady=(10,0))
            vl=ctk.CTkLabel(fc,text="—",font=(FONT_UI,28,"bold"),text_color=color); vl.pack(pady=(0,10))
            fc._vl=vl; self._folder_cards[k]=fc

        lhdr=ctk.CTkFrame(right,fg_color="transparent"); lhdr.pack(fill="x",pady=(0,6))
        ctk.CTkLabel(lhdr,text="ACTIVITY LOG",font=(FONT_UI,11,"bold"),text_color=C["t1"]).pack(side="left")
        ctk.CTkButton(lhdr,text="CLEAR",width=70,height=28,fg_color=C["card2"],hover_color=C["hover"],
            text_color=C["t1"],font=(FONT_UI,11),corner_radius=8,command=lambda:self.folder_log.clear()).pack(side="right")
        self.folder_log=LogBox(right,height=220); self.folder_log.pack(fill="x",pady=(0,10))
        ctk.CTkLabel(right,text="SAVED PROFILES",font=(FONT_UI,11,"bold"),text_color=C["t1"]).pack(anchor="w",pady=(0,6))
        self.profiles_scroll=ctk.CTkScrollableFrame(right,fg_color=C["bg2"],border_width=1,border_color=C["border"],corner_radius=10)
        self.profiles_scroll.pack(fill="both",expand=True)

    # ── LAST SCAN TAB ─────────────────────────────────────────────────────────

    def _build_scan_tab(self):
        tab=self.tabs.tab("  🔍  Last Scan  "); tab.configure(fg_color="transparent")
        self.verdict_card=ctk.CTkFrame(tab,fg_color=C["card2"],corner_radius=14,
            border_width=1,border_color=C["border"]); self.verdict_card.pack(fill="x",pady=(4,10))
        lft=ctk.CTkFrame(self.verdict_card,fg_color="transparent"); lft.pack(side="left",padx=20,pady=18)
        self.verdict_icon=ctk.CTkLabel(lft,text="⬤",font=(FONT_UI,48),text_color=C["t3"]); self.verdict_icon.pack()
        mid=ctk.CTkFrame(self.verdict_card,fg_color="transparent"); mid.pack(side="left",fill="y",pady=18)
        self.verdict_title=ctk.CTkLabel(mid,text="No scan yet",font=(FONT_UI,20,"bold"),text_color=C["t2"]); self.verdict_title.pack(anchor="w")
        self.verdict_sub=ctk.CTkLabel(mid,text="Run a scan to see results",font=(FONT_UI,13),text_color=C["t2"]); self.verdict_sub.pack(anchor="w",pady=(4,0))
        self.verdict_meta=ctk.CTkLabel(mid,text="",font=(FONT_MONO,11),text_color=C["t2"]); self.verdict_meta.pack(anchor="w",pady=(2,0))
        self.verdict_time=ctk.CTkLabel(self.verdict_card,text="",font=(FONT_MONO,11),text_color=C["t2"]); self.verdict_time.pack(side="right",padx=24)

        detail_hdr=ctk.CTkFrame(tab,fg_color="transparent"); detail_hdr.pack(fill="x",pady=(0,6))
        ctk.CTkLabel(detail_hdr,text="SCAN DETAIL",font=(FONT_UI,11,"bold"),text_color=C["t1"]).pack(side="left")
        ctk.CTkButton(detail_hdr,text="📥  Download Report",width=165,height=32,
            fg_color=C["cyan"],hover_color=C["cyan_dim"],text_color="#FFFFFF",
            font=(FONT_UI,12,"bold"),corner_radius=8,command=self._download_report).pack(side="right")
        self.vt_btn=ctk.CTkButton(detail_hdr,text="🔍  Check VirusTotal",width=175,height=32,
            fg_color=C["purple"],hover_color="#6D28D9",text_color="#FFFFFF",
            font=(FONT_UI,12,"bold"),corner_radius=8,command=self._run_vt_check)
        self.vt_btn.pack(side="right",padx=(0,8))

        self.results_box=ResultsBox(tab)
        self.results_box.pack(fill="both",expand=True)

    # ── HISTORY TAB ───────────────────────────────────────────────────────────

    def _build_history_tab(self):
        tab=self.tabs.tab("  📋  History  "); tab.configure(fg_color="transparent")
        hdr=ctk.CTkFrame(tab,fg_color="transparent"); hdr.pack(fill="x",pady=(4,10))
        ctk.CTkLabel(hdr,text="SCAN HISTORY",font=(FONT_UI,13,"bold"),text_color=C["t0"]).pack(side="left")
        ctk.CTkButton(hdr,text="🗑  Clear History",width=130,height=32,fg_color=C["red_b"],
            border_width=1,border_color=C["red"],text_color=C["red"],hover_color="#FECACA",
            font=(FONT_UI,12,"bold"),corner_radius=8,command=self._clear_history).pack(side="right",padx=(8,0))
        ctk.CTkButton(hdr,text="⟳  Refresh",width=100,height=32,fg_color=C["card2"],
            border_width=1,border_color=C["border"],text_color=C["t1"],hover_color=C["hover"],
            font=(FONT_UI,12),corner_radius=8,command=self._refresh_history).pack(side="right")

        # ── Column header using grid (Path col stretches to fill width) ──
        ch=ctk.CTkFrame(tab,fg_color=C["card2"],corner_radius=8,border_width=1,border_color=C["border2"])
        ch.pack(fill="x",pady=(0,4))
        ch.columnconfigure(1,weight=1)   # Path column stretches
        # (label, col, width, anchor)  — widths MUST match _refresh_history data rows
        _hist_hdr=[("S#",0,52,"w"),("Path",1,0,"w"),("Time",2,145,"w"),
                   ("Trigger",3,110,"w"),("Files",4,58,"center"),
                   ("Mod",5,45,"center"),("Add",6,45,"center"),("Del",7,45,"center"),
                   ("Status",8,100,"center")]
        for txt,col,w,anch in _hist_hdr:
            kw={"width":w} if w else {}
            ctk.CTkLabel(ch,text=txt,font=(FONT_UI,12,"bold"),text_color=C["t1"],
                anchor=anch,**kw).grid(row=0,column=col,
                padx=(12,4) if col==0 else 4,pady=10,sticky="ew")

        self.hist_scroll=ctk.CTkScrollableFrame(tab,fg_color=C["bg2"],border_width=1,border_color=C["border"],corner_radius=10)
        self.hist_scroll.pack(fill="both",expand=True)

    def _clear_history(self):
        if messagebox.askyesno("Clear History","Are you sure? This cannot be undone."):
            self.scan_db.clear_history(); self._refresh_history()

    # ── VIRUSTOTAL CHECK ──────────────────────────────────────────────────────

    def _run_vt_check(self):
        if self._last_results is None:
            messagebox.showwarning("No Scan","Run a scan first."); return
        api_key=VT_API_KEY.strip()
        if not api_key or api_key=="YOUR_VIRUSTOTAL_API_KEY_HERE":
            messagebox.showwarning("No API Key",
                "Add your VirusTotal API key in the code.\n\nOpen the file and set:\nVT_API_KEY = 'your_key_here'")
            return
        added=self._last_results.get("added",[])
        if not added:
            messagebox.showinfo("No Added Files","No added files in last scan. VT only checks added files."); return
        if self._vt_running:
            messagebox.showinfo("Busy","VirusTotal check already running."); return
        self._vt_running=True
        self.vt_btn.configure(text="⏳  Checking...",state="disabled",fg_color=C["t2"])
        sep="─"*68
        self.results_box.write(f"\n{sep}\n","muted")
        self.results_box.write(f"  🔍  VIRUSTOTAL CHECK — {len(added)} file(s)\n","header")
        self.results_box.write(f"  Checking against 70+ antivirus engines...\n","muted")
        threading.Thread(target=self._vt_thread,args=(added,),daemon=True).start()

    def _vt_thread(self,added_files):
        def progress(done,total,path):
            short=("..."+path[-34:]) if len(path)>34 else path
            self._q(self.prog_label.configure,{"text":f"VT: {short}"})
            self._q(self.prog_pct.configure,{"text":f"Checking {done}/{total}"})
            self._q(self.results_box.write,f"\n  Checking ({done}/{total}): {path}\n","muted")
        try:
            vt_results=vt_check_added_files(added_files,progress_cb=progress)
            self._last_vt_results=vt_results
            if self._session_scans:
                self._session_scans[-1]["vt"]=vt_results
            self._q(self._on_vt_done,vt_results)
        except Exception as e:
            self._q(self.results_box.write,f"\n  VT Error: {e}\n","vt_err")
            self._q(self.vt_btn.configure,{"text":"🔍  Check VirusTotal","state":"normal","fg_color":C["purple"]})
            self._vt_running=False

    def _on_vt_done(self,vt_results):
        self._vt_running=False
        self.vt_btn.configure(text="✅  VT Done — Re-check",state="normal",fg_color=C["green"])
        sep="─"*68
        mal=sum(1 for r in vt_results if r["vt"].get("status")=="malicious")
        sus=sum(1 for r in vt_results if r["vt"].get("status")=="suspicious")
        cln=sum(1 for r in vt_results if r["vt"].get("status")=="clean")
        unk=sum(1 for r in vt_results if r["vt"].get("status")=="unknown")
        err=sum(1 for r in vt_results if r["vt"].get("status")=="error")
        self.results_box.write(f"\n  {sep}\n","muted")
        self.results_box.write(f"  VIRUSTOTAL RESULTS\n","header")
        self.results_box.write(f"  {sep}\n\n","muted")
        for r in vt_results:
            vt=r["vt"]; s=vt.get("status","")
            self.results_box.write(f"  📄  {r['path']}\n","normal")
            self.results_box.write(f"      HASH   : {r['hash']}\n","muted")
            if s=="malicious":   icon="🔴"; badge=f"MALICIOUS — {vt.get('score','?')} engines flagged"; ctag="vt_mal"
            elif s=="suspicious":icon="🟠"; badge=f"SUSPICIOUS — {vt.get('score','?')} engines flagged"; ctag="vt_sus"
            elif s=="clean":     icon="🟢"; badge=f"CLEAN — 0/{vt.get('total','?')} engines"; ctag="vt_clean"
            elif s=="unknown":   icon="🟡"; badge="NOT IN DATABASE"; ctag="vt_unk"
            else:                icon="⚪"; badge=f"ERROR — {vt.get('error_msg','')}"; ctag="vt_err"
            self.results_box.write(f"      STATUS : {icon}  {badge}\n",ctag)
            if vt.get("total",0)>0:
                self.results_box.write(
                    f"      SCORE  : {vt.get('malicious',0)} malicious  |  "
                    f"{vt.get('suspicious',0)} suspicious  |  "
                    f"{vt.get('undetected',0)} undetected  |  "
                    f"Total: {vt.get('total',0)} engines\n","vt_score")
            self.results_box.write("\n","normal")
        self.results_box.write(f"  {sep}\n","muted")
        self.prog_label.configure(text="VirusTotal complete")
        self.prog_pct.configure(text=f"{len(vt_results)} file(s) checked")
        if mal>0: send_notification("⚠️ MALWARE DETECTED!",f"{mal} file(s) flagged MALICIOUS by VirusTotal!")
        elif sus>0: send_notification("⚠️ Suspicious Files",f"{sus} file(s) SUSPICIOUS by VirusTotal.")

    # ── DOWNLOAD REPORT ───────────────────────────────────────────────────────

    def _download_report(self):
        if self._last_results is None:
            messagebox.showwarning("No Scan","Run a scan first, then download the report."); return
        if not FPDF_AVAILABLE:
            messagebox.showerror("Library Missing",
                "fpdf2 is not installed.\n\nOpen a terminal and run:\n"
                "  pip install fpdf2\n\nThen restart the app.")
            return
        try:
            # Build extra sections from all session scans except the very last one
            extra=[]
            for sc in self._session_scans[:-1]:
                extra.append({"drive":sc["drive"],"results":sc["results"],
                              "session_id":sc["session_id"],"timestamp":sc["timestamp"],
                              "trigger":sc["trigger"],"vt":sc.get("vt")})
            generate_pdf_report(
                self._last_drive, self._last_results,
                self._last_session_id, self._last_timestamp, self._last_trigger,
                vt_results=self._last_vt_results,
                extra_sections=extra if extra else None
            )
        except Exception as e:
            messagebox.showerror("Report Error",
                f"Could not generate PDF report.\n\nError: {e}\n\n"
                "Make sure fpdf2 is installed: pip install fpdf2")

    # ══════════════════ FOLDER LOGIC ══════════════════

    def _browse_baseline_folder(self):
        folder=filedialog.askdirectory(title="Select Folder to Baseline")
        if folder:
            self._folder_path=folder; self.bl_path_label.configure(text=folder,text_color=C["t0"])
            self.profile_entry.delete(0,"end"); self.profile_entry.insert(0,os.path.basename(folder))

    def _browse_scan_folder(self):
        folder=filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            self._scan_folder_path=folder; self.scan_path_label.configure(text=folder,text_color=C["t0"])

    def _generate_folder_baseline(self):
        folder=self._folder_path; profile=self.profile_entry.get().strip()
        if not folder: messagebox.showwarning("No Folder","Select a folder first."); return
        if not profile: messagebox.showwarning("No Name","Enter a profile name."); return
        if not os.path.isdir(folder): messagebox.showerror("Invalid","Folder does not exist."); return
        if self._baseline_creating: messagebox.showinfo("Busy","Already creating a baseline."); return
        self.folder_log.append(f"Generating baseline for '{profile}' ...","cyan")
        threading.Thread(target=self._run_folder_baseline,args=(folder,profile),daemon=True).start()

    def _run_folder_baseline(self,folder,profile):
        self._baseline_creating=True
        def progress(done,total,fname):
            pct=done/total if total else 0
            short=("..."+fname[-34:]) if len(fname)>34 else fname
            self._q(self.prog_bar.set,pct)
            self._q(self.prog_label.configure,{"text":short})
            self._q(self.prog_pct.configure,{"text":f"{done}/{total} ({int(pct*100)}%)"})
        try:
            key=f"[FOLDER] {profile}"
            hashes=scan_drive(folder,progress_cb=progress)
            self.baseline_db.save_baseline(key,hashes); count=len(hashes)
            self._q(self.folder_log.append,f"Baseline created: {count} files","success")
            self._q(self._fcard_set,"files",str(count))
            self._q(self.prog_bar.set,1)
            self._q(self.prog_label.configure,{"text":"Baseline complete"})
            self._q(self.prog_pct.configure,{"text":f"{count:,} files indexed"})
            self._q(self._refresh_profiles)
            send_notification("Folder Baseline Created",f"'{profile}' — {count} files indexed.")
        except Exception as e:
            self._q(self.folder_log.append,f"Baseline failed: {e}","error")
        finally:
            self._baseline_creating=False

    def _on_profile_selected(self,value):
        if value and value!="— select profile —":
            for row in self.baseline_db.list_all():
                key=row[0]
                if key.startswith("[FOLDER] "):
                    parts=key.replace("[FOLDER] ","")
                    pname=parts.split("::")[0] if "::" in parts else parts
                    if pname==value:
                        if "::" in parts:
                            folder=parts.split("::",1)[1]
                            self._scan_folder_path=folder
                            self.scan_path_label.configure(text=folder,text_color=C["t0"])
                        break

    def _start_folder_scan(self):
        pv=self.profile_var.get()
        if not pv or pv=="— select profile —": messagebox.showwarning("No Profile","Select a profile."); return
        sp=getattr(self,"_scan_folder_path","")
        if not sp: messagebox.showwarning("No Folder","Select a folder to scan."); return
        if not os.path.isdir(sp): messagebox.showerror("Invalid","Folder does not exist."); return
        if self._folder_scanning: messagebox.showinfo("Busy","Scan already running."); return
        key=f"[FOLDER] {pv}"
        if not self.baseline_db.has_baseline(key):
            messagebox.showwarning("No Baseline",f"No baseline for '{pv}'.\n\nGenerate baseline first."); return
        threading.Thread(target=self._run_folder_scan,args=(key,sp,pv),daemon=True).start()

    def _run_folder_scan(self,key,folder,profile):
        self._folder_scanning=True
        def progress(done,total,fname):
            pct=done/total if total else 0
            short=("..."+fname[-34:]) if len(fname)>34 else fname
            self._q(self.prog_bar.set,pct)
            self._q(self.prog_label.configure,{"text":short})
            self._q(self.prog_pct.configure,{"text":f"{done}/{total} ({int(pct*100)}%)"})
        try:
            self._q(self.folder_log.append,f"Scanning '{profile}' ...","cyan")
            baseline=self.baseline_db.get_baseline(key)
            current=scan_drive(folder,progress_cb=progress)
            results=compare(baseline,current)
            self.baseline_db.update_last_scan(key)
            session_id=_next_session_scan_id()
            self.scan_db.save_scan(folder,results,f"Folder: {profile}",session_id)
            self._q(self._on_folder_scan_done,folder,results,session_id,profile)
        except Exception as e:
            self._q(self.folder_log.append,f"Scan failed: {e}","error")
        finally:
            self._folder_scanning=False

    def _on_folder_scan_done(self,folder,results,session_id,profile):
        m=len(results["modified"]); a=len(results["added"]); d=len(results["deleted"])
        rn=len(results.get("renamed",[])); total=results["total"]
        clean=(m+a+d+rn)==0; now=datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._fcard_set("files",str(total)); self._fcard_set("modified",str(m))
        self._fcard_set("added",str(a)); self._fcard_set("deleted",str(d))
        self.prog_bar.set(1)
        self.prog_label.configure(text=f"Scan S#{session_id} complete")
        self.prog_pct.configure(text=f"{total:,} files checked")
        rename_only=(m+a+d)==0 and rn>0
        if clean:
            self.folder_log.append(f"Scan S#{session_id} — {total} files — CLEAN ✅","success")
        elif rename_only:
            self.folder_log.append(f"Scan S#{session_id} — {total} files — WARNING 🔄 ({rn} renamed/moved)","warn")
            for x in results.get("renamed",[]):
                ev=x.get("event_type","renamed").upper()
                self.folder_log.append(f"  🔄  [{ev}]  {x['old_path']}  →  {x['new_path']}","warn")
        else:
            self.folder_log.append(f"Scan S#{session_id} — {total} files — COMPROMISED ⚠️","warn")
            for x in results["modified"]: self.folder_log.append(f"  ⚠  {x['path']}","error")
            for x in results["added"]:    self.folder_log.append(f"  ➕  {x['path']}","warn")
            for x in results["deleted"]:  self.folder_log.append(f"  🗑  {x['path']}","error")
            for x in results.get("renamed",[]):
                ev=x.get("event_type","renamed").upper()
                self.folder_log.append(f"  🔄  [{ev}]  {x['old_path']}  →  {x['new_path']}","warn")
        self._last_results=results; self._last_drive=folder
        self._last_session_id=session_id; self._last_timestamp=now
        self._last_trigger=f"Folder: {profile}"; self._last_vt_results=None
        self._session_scans.append({"drive":folder,"results":results,"session_id":session_id,
                                    "timestamp":now,"trigger":f"Folder: {profile}","vt":None})
        self.vt_btn.configure(text="🔍  Check VirusTotal",state="normal",fg_color=C["purple"])
        self._populate_results(folder,results,now,session_id)
        self._refresh_history(); self.tabs.set("  🔍  Last Scan  ")
        if clean: send_notification("Folder Integrity OK",f"'{profile}' — {total} unchanged.")
        else: send_notification("Compromised!",f"'{profile}' — {m} mod, {a} add, {d} del, {rn} renamed")

    def _fcard_set(self,key,value):
        if key in self._folder_cards: self._folder_cards[key]._vl.configure(text=value)

    def _refresh_profiles(self):
        all_profiles=self.baseline_db.list_all()
        fp=[(r[0],r[1],r[2]) for r in all_profiles if r[0].startswith("[FOLDER] ")]
        names=[]
        for key,total,created in fp:
            parts=key.replace("[FOLDER] ","")
            pname=parts.split("::")[0] if "::" in parts else parts
            names.append(pname)
        if names:
            self.profile_menu.configure(values=names)
            if self.profile_var.get()=="— select profile —": self.profile_var.set(names[0])
        else:
            self.profile_menu.configure(values=["— select profile —"])
            self.profile_var.set("— select profile —")
        for w in self.profiles_scroll.winfo_children(): w.destroy()
        if not fp:
            ctk.CTkLabel(self.profiles_scroll,text="No profiles yet. Create a baseline above.",
                font=(FONT_UI,12),text_color=C["t2"]).pack(pady=16); return
        for key,total,created in fp:
            parts=key.replace("[FOLDER] ","")
            pname=parts.split("::")[0] if "::" in parts else parts
            date_str=created[:10] if created else "—"
            pf=ctk.CTkFrame(self.profiles_scroll,fg_color=C["card"],corner_radius=8,border_width=1,border_color=C["border"]); pf.pack(fill="x",pady=3)
            pfi=ctk.CTkFrame(pf,fg_color="transparent"); pfi.pack(fill="x",padx=10,pady=8)
            ctk.CTkLabel(pfi,text="◆",font=(FONT_UI,14),text_color=C["cyan"]).pack(side="left",padx=(0,8))
            info=ctk.CTkFrame(pfi,fg_color="transparent"); info.pack(side="left",fill="x",expand=True)
            ctk.CTkLabel(info,text=pname,font=(FONT_MONO,12,"bold"),text_color=C["t0"],anchor="w").pack(anchor="w")
            ctk.CTkLabel(info,text=f"{total:,} files  ·  {date_str}",font=(FONT_UI,10),text_color=C["t2"],anchor="w").pack(anchor="w")
            ctk.CTkButton(pfi,text="✕",width=28,height=28,fg_color=C["red_b"],hover_color=C["red"],
                text_color=C["red"],border_width=1,border_color=C["red"],font=(FONT_UI,12),corner_radius=6,
                command=lambda k=key:self._delete_profile(k)).pack(side="right",padx=(4,0))
            ctk.CTkButton(pfi,text="🔄",width=28,height=28,fg_color=C["yellow_b"],hover_color=C["gold"],
                text_color=C["gold"],border_width=1,border_color=C["gold"],font=(FONT_UI,12),corner_radius=6,
                command=lambda k=key,p=pname:self._update_profile(k,p)).pack(side="right",padx=(0,4))

    def _delete_profile(self,key):
        parts=key.replace("[FOLDER] ",""); pname=parts.split("::")[0] if "::" in parts else parts
        if messagebox.askyesno("Delete Profile",f"Delete baseline for '{pname}'?"):
            self.baseline_db.delete_baseline(key)
            self.folder_log.append(f"Profile '{pname}' deleted","warn"); self._refresh_profiles()

    def _update_profile(self,key,pname):
        if self._baseline_creating: messagebox.showinfo("Busy","Baseline update in progress."); return
        parts=key.replace("[FOLDER] ","")
        folder=parts.split("::",1)[1] if "::" in parts else getattr(self,"_scan_folder_path","")
        if not folder or not os.path.isdir(folder):
            folder=filedialog.askdirectory(title=f"Select folder for '{pname}'")
            if not folder: return
        if messagebox.askyesno("Update Baseline",f"Re-hash '{pname}'?\nFolder: {folder}"):
            self.folder_log.append(f"Updating baseline for '{pname}' ...","cyan")
            threading.Thread(target=self._run_profile_update,args=(key,folder,pname),daemon=True).start()

    def _run_profile_update(self,key,folder,pname):
        self._baseline_creating=True
        def progress(done,total,fname):
            pct=done/total if total else 0
            short=("..."+fname[-34:]) if len(fname)>34 else fname
            self._q(self.prog_bar.set,pct)
            self._q(self.prog_label.configure,{"text":short})
            self._q(self.prog_pct.configure,{"text":f"{done}/{total} ({int(pct*100)}%)"})
        try:
            hashes=scan_drive(folder,progress_cb=progress)
            self.baseline_db.save_baseline(key,hashes); count=len(hashes)
            self._q(self.folder_log.append,f"Updated '{pname}': {count} files","success")
            self._q(self.prog_bar.set,1)
            self._q(self.prog_label.configure,{"text":"Update complete"})
            self._q(self.prog_pct.configure,{"text":f"{count:,} files re-indexed"})
            self._q(self._refresh_profiles)
            send_notification("Baseline Updated",f"'{pname}' — {count} files re-indexed.")
        except Exception as e:
            self._q(self.folder_log.append,f"Update failed: {e}","error")
        finally:
            self._baseline_creating=False

    # ══════════════════ USB MONITOR LOGIC ══════════════════

    def _monitor_loop(self):
        if WIN32_AVAILABLE: pythoncom.CoInitialize()
        while not self._stop_event.is_set():
            try:
                self._check_drives()
                if self._monitoring_active and WIN32_AVAILABLE:
                    self._check_explorer()
            except Exception as e:
                self._q(self.log.append,f"Monitor error: {e}","error")
            time.sleep(2)
        if WIN32_AVAILABLE: pythoncom.CoUninitialize()

    def _check_drives(self):
        current=set(get_removable_drives())
        for drive in current-self._known_drives:
            self._known_drives.add(drive); self._explorer_open[drive]=False
            self._q(self._on_drive_connected,drive)
        for drive in self._known_drives-current:
            self._known_drives.discard(drive); self._explorer_open.pop(drive,None)
            self._q(self._on_drive_disconnected,drive)

    def _check_explorer(self):
        open_now=get_explorer_drive_windows()
        for drive in list(self._known_drives):
            was_open=self._explorer_open.get(drive,False); is_open=drive.upper() in open_now
            if is_open and not was_open: self._explorer_open[drive]=True; self._q(self._on_explorer_opened,drive)
            elif not is_open and was_open: self._explorer_open[drive]=False; self._q(self._on_explorer_closed,drive)

    def _on_drive_connected(self,drive):
        self.log.append(f"Drive detected: {drive}","success"); self._update_drives_panel()
        if self._monitoring_active:
            if self.baseline_db.has_baseline(drive):
                self.log.append(f"Baseline EXISTS for {drive} — ready","success")
            else:
                self.log.append(f"No baseline for {drive} — auto-creating...","warn")
                threading.Thread(target=self._auto_baseline,args=(drive,),daemon=True).start()
        else:
            if self.baseline_db.has_baseline(drive):
                self.log.append(f"Drive {drive} ready — baseline exists ✅","success")
            else:
                self.log.append(f"Drive {drive} — no baseline yet","warn")

    def _on_drive_disconnected(self,drive):
        self.log.append(f"Drive removed: {drive}  (baseline preserved)","warn"); self._update_drives_panel()

    def _on_explorer_opened(self,drive):
        self.log.append(f"Explorer opened: {drive} — watching for close","cyan")

    def _on_explorer_closed(self,drive):
        self.log.append(f"Explorer CLOSED: {drive} — auto-scan triggered!","warn")
        if not self._scanning and not self._baseline_creating:
            threading.Thread(target=self._run_scan,args=(drive,"Explorer closed"),daemon=True).start()

    def _auto_baseline(self,drive):
        self._baseline_creating=True
        def progress(done,total,fname):
            pct=done/total if total else 0
            short=("..."+fname[-34:]) if len(fname)>34 else fname
            self._q(self.prog_bar.set,pct); self._q(self.prog_label.configure,{"text":short})
            self._q(self.prog_pct.configure,{"text":f"{done}/{total} ({int(pct*100)}%)"})
        try:
            hashes=scan_drive(drive,progress_cb=progress)
            self.baseline_db.save_baseline(drive,hashes); self._q(self._on_baseline_done,drive,len(hashes))
        except Exception as e: self._q(self.log.append,f"Baseline FAILED: {e}","error")
        finally: self._baseline_creating=False

    def _on_baseline_done(self,drive,count):
        self.log.append(f"Baseline CREATED — {count:,} files for {drive}","success")
        self.prog_bar.set(1); self.prog_label.configure(text="Baseline complete")
        self.prog_pct.configure(text=f"{count:,} files indexed"); self._cards["files"].set_value(f"{count:,}")
        self._update_drives_panel(); send_notification("Baseline Created",f"{drive} — {count:,} files indexed.")

    def _run_scan(self,drive,trigger):
        if self._scanning: return
        self._scanning=True
        def progress(done,total,fname):
            pct=done/total if total else 0
            short=("..."+fname[-34:]) if len(fname)>34 else fname
            self._q(self.prog_bar.set,pct); self._q(self.prog_label.configure,{"text":short})
            self._q(self.prog_pct.configure,{"text":f"{done}/{total} ({int(pct*100)}%)"})
        try:
            self._q(self.log.append,f"Scan started  [trigger: {trigger}]","cyan")
            baseline=self.baseline_db.get_baseline(drive); current=scan_drive(drive,progress_cb=progress)
            results=compare(baseline,current); self.baseline_db.update_last_scan(drive)
            session_id=_next_session_scan_id()
            self.scan_db.save_scan(drive,results,trigger,session_id)
            self._q(self._on_scan_done,drive,results,session_id,trigger)
        except Exception as e: self._q(self.log.append,f"Scan FAILED: {e}","error")
        finally: self._scanning=False

    def _on_scan_done(self,drive,results,session_id,trigger="Manual scan"):
        m=len(results["modified"]); a=len(results["added"]); d=len(results["deleted"])
        rn=len(results.get("renamed",[])); total=results["total"]
        clean=(m+a+d+rn)==0; rename_only=(m+a+d)==0 and rn>0; now=datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._cards["files"].set_value(f"{total:,}"); self._cards["modified"].set_value(str(m))
        self._cards["added"].set_value(str(a)); self._cards["deleted"].set_value(str(d))
        if clean:
            self.log.append(f"Scan S#{session_id} — CLEAN ✅  ({total:,} files)","success")
        elif rename_only:
            self.log.append(f"Scan S#{session_id} — WARNING 🔄  {rn} file(s) renamed/moved (content intact)","warn")
            for x in results.get("renamed",[]):
                ev=x.get("event_type","renamed").upper()
                self.log.append(f"  🔄  [{ev}]  {x['old_path']}  →  {x['new_path']}","warn")
        else:
            self.log.append(f"Scan S#{session_id} — COMPROMISED ⚠️  mod={m} add={a} del={d} renamed={rn}","error")
            for x in results.get("renamed",[]):
                ev=x.get("event_type","renamed").upper()
                self.log.append(f"  🔄  [{ev}]  {x['old_path']}  →  {x['new_path']}","warn")
        self.prog_bar.set(1); self.prog_label.configure(text=f"Scan S#{session_id} complete")
        self.prog_pct.configure(text=f"{total:,} files checked")
        self._last_results=results; self._last_drive=drive
        self._last_session_id=session_id; self._last_timestamp=now
        self._last_trigger=trigger; self._last_vt_results=None
        self._session_scans.append({"drive":drive,"results":results,"session_id":session_id,
                                    "timestamp":now,"trigger":trigger,"vt":None})
        self.vt_btn.configure(text="🔍  Check VirusTotal",state="normal",fg_color=C["purple"])
        self._populate_results(drive,results,now,session_id); self._refresh_history()
        if clean: send_notification("Drive Integrity OK",f"{drive} — {total:,} unchanged.")
        else: send_notification("Integrity Compromised!",f"{drive} — {m} mod, {a} add, {d} del, {rn} renamed")
        self.tabs.set("  🔍  Last Scan  ")
        if a>0: self.log.append(f"{a} new file(s) — click '🔍 Check VirusTotal' in Last Scan tab","warn")

    def _populate_results(self,drive,results,timestamp,session_id):
        m=len(results["modified"]); a=len(results["added"]); d=len(results["deleted"])
        rn=len(results.get("renamed",[])); clean=(m+a+d+rn)==0
        rename_only=(m+a+d)==0 and rn>0
        if clean:
            self.verdict_icon.configure(text="✅",text_color=C["green"])
            self.verdict_title.configure(text="INTEGRITY VERIFIED",text_color=C["green"])
            self.verdict_sub.configure(text=f"All {results['total']:,} files match baseline",text_color=C["green"])
            self.verdict_meta.configure(text=f"Path: {drive}  ·  Session S#{session_id}",text_color=C["t2"])
        elif rename_only:
            self.verdict_icon.configure(text="🔄",text_color=C["yellow"])
            self.verdict_title.configure(text="INTEGRITY WARNING",text_color=C["yellow"])
            self.verdict_sub.configure(text=f"{rn} file(s) renamed/moved — content unchanged  out of {results['total']:,}",text_color=C["yellow"])
            self.verdict_meta.configure(text=f"Path: {drive}  ·  Session S#{session_id}",text_color=C["t2"])
        else:
            self.verdict_icon.configure(text="⚠️",text_color=C["red"])
            self.verdict_title.configure(text="INTEGRITY COMPROMISED",text_color=C["red"])
            parts=[]
            if m: parts.append(f"{m} modified")
            if a: parts.append(f"{a} added")
            if d: parts.append(f"{d} deleted")
            if rn: parts.append(f"{rn} renamed/moved")
            self.verdict_sub.configure(text="  ·  ".join(parts)+f"  out of {results['total']:,}",text_color=C["yellow"])
            self.verdict_meta.configure(text=f"Path: {drive}  ·  Session S#{session_id}",text_color=C["t2"])
        self.verdict_time.configure(text=timestamp)
        self.results_box.clear()
        sep="─"*68
        self.results_box.write(f"  SCAN REPORT  S#{session_id}\n","header")
        self.results_box.write(f"  {sep}\n","muted")
        self.results_box.write(f"  Path       :  {drive}\n","normal")
        self.results_box.write(f"  Timestamp  :  {timestamp}\n","normal")
        self.results_box.write(f"  Total files:  {results['total']:,}\n","normal")
        self.results_box.write(f"  Result     :  {'✅ CLEAN' if clean else ('🔄 WARNING' if rename_only else '⚠️  COMPROMISED')}\n",
                               "vt_clean" if clean else ("vt_unk" if rename_only else "vt_mal"))
        self.results_box.write(f"  {sep}\n\n","muted")
        if results["modified"]:
            self.results_box.write(f"  ✏️   MODIFIED FILES  ({m})\n","vt_sus")
            self.results_box.write(f"  {sep}\n","muted")
            for x in results["modified"]:
                self.results_box.write(f"\n  📄  {x['path']}\n","normal")
                self.results_box.write(f"      OLD: {x['old_hash']}\n","muted")
                self.results_box.write(f"      NEW: {x['new_hash']}\n","vt_sus")
        if results.get("renamed"):
            self.results_box.write(f"\n\n  🔄  RENAMED / MOVED FILES  ({rn})\n","vt_unk")
            self.results_box.write(f"  {sep}\n","muted")
            for x in results["renamed"]:
                ev = x.get("event_type","renamed").upper()
                icon = "📝" if ev=="RENAMED" else "📁"
                self.results_box.write(f"\n  {icon}  [{ev}]  {x['old_path']}\n","normal")
                self.results_box.write(f"      FROM: {x['old_path']}\n","muted")
                self.results_box.write(f"      TO  : {x['new_path']}\n","vt_unk")
                self.results_box.write(f"      HASH: {x['hash']}\n","muted")
        if results["added"]:
            self.results_box.write(f"\n\n  ➕  ADDED FILES  ({a})\n","vt_clean")
            self.results_box.write(f"  {sep}\n","muted")
            for x in results["added"]:
                self.results_box.write(f"\n  📄  {x['path']}\n","normal")
                self.results_box.write(f"      HASH: {x['new_hash']}\n","muted")
            self.results_box.write(f"\n  💡  Click '🔍 Check VirusTotal' above to scan added files.\n","vt_score")
        if results["deleted"]:
            self.results_box.write(f"\n\n  🗑   DELETED FILES  ({d})\n","vt_mal")
            self.results_box.write(f"  {sep}\n","muted")
            for x in results["deleted"]:
                self.results_box.write(f"\n  📄  {x['path']}\n","normal")
                self.results_box.write(f"      SHA-256: {x['old_hash']}\n","muted")
        if clean:
            self.results_box.write("\n  ✅  All files match baseline exactly.\n","vt_clean")

    def _refresh_history(self):
        for w in self.hist_scroll.winfo_children(): w.destroy()
        rows=self.scan_db.get_history()
        if not rows:
            ctk.CTkLabel(self.hist_scroll,text="No scan history yet.",font=(FONT_UI,13),text_color=C["t2"]).pack(pady=20); return
        for row in rows:
            if len(row)==10:
                db_id,sess_id,drive,stime,trigger,total,mod,add,delt,status=row
            elif len(row)==9:
                db_id,drive,stime,trigger,total,mod,add,delt,status=row; sess_id="?"
            elif len(row)==8:
                db_id,drive,stime,total,mod,add,delt,status=row; trigger="legacy"; sess_id="?"
            else:
                continue
            clean=status=="CLEAN"; warn=status=="WARNING"
            sc  = C["green"] if clean else (C["yellow"] if warn else C["red"])
            sbg = C["green_b"] if clean else (C["yellow_b"] if warn else C["red_b"])
            # ── Each history row uses grid with Path column stretching ──
            rf=ctk.CTkFrame(self.hist_scroll,fg_color=C["card"],corner_radius=10,
                            border_width=1,border_color=C["border"])
            rf.pack(fill="x",pady=3)
            rf.columnconfigure(1,weight=1)  # Path stretches
            ctk.CTkFrame(rf,width=4,corner_radius=2,fg_color=sc).place(x=0,y=0,relheight=1)
            sp=drive[-50:] if len(drive)>50 else drive
            # col 0 - S#  (width=52 matches header)
            ctk.CTkLabel(rf,text=f"S#{sess_id}",font=(FONT_MONO,12),text_color=C["t0"],
                anchor="w",width=52).grid(row=0,column=0,padx=(12,4),pady=10,sticky="w")
            # col 1 - Path (stretches)
            ctk.CTkLabel(rf,text=sp,font=(FONT_MONO,11),text_color=C["t0"],
                anchor="w").grid(row=0,column=1,padx=4,pady=10,sticky="ew")
            # col 2 - Time  (width=145)
            ctk.CTkLabel(rf,text=stime[:16],font=(FONT_MONO,11),text_color=C["t0"],
                anchor="w",width=145).grid(row=0,column=2,padx=4,pady=10,sticky="w")
            # col 3 - Trigger  (width=110)
            ctk.CTkLabel(rf,text=str(trigger)[:16],font=(FONT_MONO,11),text_color=C["t0"],
                anchor="w",width=110).grid(row=0,column=3,padx=4,pady=10,sticky="w")
            # col 4-7 numbers  (widths match header: 58, 45, 45, 45)
            for val,col,w in [(f"{total:,}",4,58),(str(mod),5,45),(str(add),6,45),(str(delt),7,45)]:
                ctk.CTkLabel(rf,text=val,font=(FONT_MONO,12),text_color=C["t0"],
                    anchor="center",width=w).grid(row=0,column=col,padx=4,pady=10,sticky="ew")
            # col 8 - Status badge  (width=100 matches header)
            badge=ctk.CTkFrame(rf,fg_color=sbg,corner_radius=6,width=100)
            badge.grid(row=0,column=8,padx=(4,12),pady=6,sticky="ew")
            badge.pack_propagate(False)
            ctk.CTkLabel(badge,text=status,font=(FONT_UI,11,"bold"),text_color=sc).pack(expand=True)

    def _render_no_drives(self):
        ctk.CTkLabel(self.drives_frame,text="No removable drives detected\nPlug in a USB drive...",
            font=(FONT_UI,11),text_color=C["t2"],justify="center").pack(pady=8)

    def _update_drives_panel(self):
        for w in self.drives_frame.winfo_children(): w.destroy()
        if not self._known_drives: self._render_no_drives(); return
        for drive in sorted(self._known_drives):
            has_bl=self.baseline_db.has_baseline(drive); exp_open=self._explorer_open.get(drive,False)
            badge="✅" if has_bl else "⏳"; eye="  👁" if exp_open else ""; selected=drive==self._selected_drive
            ctk.CTkButton(self.drives_frame,text=f"  💾  {drive}  {badge}{eye}",
                fg_color=C["cyan"] if selected else C["card2"],
                hover_color=C["cyan_dim"] if selected else C["hover"],
                text_color="#FFFFFF" if selected else C["t0"],anchor="w",height=34,corner_radius=8,
                font=(FONT_UI,12,"bold" if selected else "normal"),
                command=lambda d=drive:self._select_drive(d)).pack(fill="x",pady=2)

    def _select_drive(self,drive): self._selected_drive=drive; self._update_drives_panel()

    def _create_usb_baseline(self):
        drive=self._selected_drive or (sorted(self._known_drives)[0] if self._known_drives else None)
        if not drive: messagebox.showwarning("No Drive","No removable drive connected."); return
        if self._baseline_creating: messagebox.showinfo("Busy","Baseline creation in progress."); return
        if self.baseline_db.has_baseline(drive):
            if not messagebox.askyesno("Baseline Exists",f"Baseline exists for {drive}.\n\nOverwrite?"): return
        self.log.append(f"Creating baseline for {drive} ...","cyan")
        threading.Thread(target=self._auto_baseline,args=(drive,),daemon=True).start()

    def _manual_scan(self):
        drive=self._selected_drive or (sorted(self._known_drives)[0] if self._known_drives else None)
        if not drive: messagebox.showwarning("No Drive","No removable drive connected."); return
        if not self.baseline_db.has_baseline(drive):
            messagebox.showwarning("No Baseline",f"No baseline for {drive}.\n\nClick CREATE BASELINE first."); return
        if self._scanning: messagebox.showinfo("Busy","Scan already running."); return
        threading.Thread(target=self._run_scan,args=(drive,"Manual scan"),daemon=True).start()

    def _update_usb_baseline(self):
        drive=self._selected_drive or (sorted(self._known_drives)[0] if self._known_drives else None)
        if not drive: messagebox.showwarning("No Drive","No removable drive connected."); return
        if not self.baseline_db.has_baseline(drive):
            messagebox.showwarning("No Baseline",f"No baseline for {drive}."); return
        if self._baseline_creating: messagebox.showinfo("Busy","Baseline update in progress."); return
        if messagebox.askyesno("Update Baseline",f"Re-hash all files on {drive}?"):
            self.log.append(f"Updating baseline for {drive} ...","cyan")
            threading.Thread(target=self._auto_baseline,args=(drive,),daemon=True).start()

    def _delete_usb_baseline(self):
        drive=self._selected_drive
        if not drive: messagebox.showwarning("Select Drive","Click a drive in the sidebar first."); return
        if not self.baseline_db.has_baseline(drive): messagebox.showinfo("Not Found",f"No baseline for {drive}."); return
        if messagebox.askyesno("Delete Baseline",f"Permanently delete baseline for {drive}?"):
            self.baseline_db.delete_baseline(drive)
            self.log.append(f"Baseline deleted for {drive}","warn"); self._update_drives_panel()

    def _q(self,fn,*args): self._ui_queue.put((fn,args))

    def _process_queue(self):
        try:
            while True: fn,args=self._ui_queue.get_nowait(); fn(*args)
        except queue.Empty: pass
        self.after(80,self._process_queue)

    def _set_status(self,text,color=None): pass
    def _set_sub(self,text): pass
    def _on_close(self): self._stop_event.set(); self.destroy()

if __name__=="__main__":
    if sys.platform!="win32":
        print("Explorer window monitoring requires Windows.")
        print("Drive detection and hashing will still work.\n")
    app=App(); app.mainloop()