import os
import sys
import time
import json
import hashlib
import platform
import subprocess
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QScrollArea, QGroupBox,
    QPushButton, QGridLayout, QSizePolicy, QStackedLayout, QFileDialog, QMessageBox,
    QHBoxLayout, QCheckBox, QComboBox
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject

# Try to use system trash instead of permanent delete
try:
    from send2trash import send2trash
except Exception:
    send2trash = None

IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.bmp', '.gif')

# --- Config ---
HASH_ALGORITHM = "sha256"
USE_PROCESSES = True  # When False, the quick stage will use threads (often faster for IO-bound reads)
ENABLE_CACHE = True
ENABLE_TWO_STAGE = True
QUICK_HASH_BYTES = 256 * 1024
MAX_WORKERS = None  # None -> auto (cpu_count - 1)

APP_NAME = "DuplicateGallery"  # used for centralized cache folder naming
CACHE_ENV_VAR = "DUPGALLERY_CACHE_DIR"  # optional env override for cache root

# --- Hash selection ---
def get_hash_function(algo):
    return {
        "sha256": hashlib.sha256,
        "md5": hashlib.md5,
        "blake2b": hashlib.blake2b
    }.get(algo.lower(), hashlib.sha256)

HASH_FUNC = get_hash_function(HASH_ALGORITHM)

# --- Centralized cache path helpers ---
def _user_cache_dir():
    # Env override always wins
    env_dir = os.getenv(CACHE_ENV_VAR)
    if env_dir:
        return Path(env_dir)

    sysname = platform.system()
    if sysname == "Windows":
        base = os.getenv("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        return Path(base) / APP_NAME / "cache"
    elif sysname == "Darwin":
        return Path.home() / "Library" / "Caches" / APP_NAME
    else:
        return Path.home() / ".cache" / APP_NAME.lower()

def _safe_name_from_root(root_dir: str) -> str:
    # readable hint + stable hash (avoid overly long filenames)
    hint = root_dir.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    h = hashlib.sha1(os.path.abspath(root_dir).encode("utf-8")).hexdigest()[:12]
    # Keep path lengths sane
    name = f"{hint}__{h}.json"
    return name[:180] if len(name) > 180 else name

def get_cache_path_for_root(root_dir: str) -> Path:
    d = _user_cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / _safe_name_from_root(root_dir)

# --- Hashers ---
def full_file_hash(path, block_size=4 * 1024 * 1024):
    h = HASH_FUNC()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            h.update(chunk)
    return h.hexdigest()

def quick_file_hash(path, first_n=QUICK_HASH_BYTES):
    h = HASH_FUNC()
    with open(path, "rb") as f:
        chunk = f.read(first_n)
        h.update(chunk)
    return h.hexdigest()

def compute_quick(path):
    try:
        return path, quick_file_hash(path)
    except Exception:
        return path, None

def compute_full(path):
    try:
        return path, full_file_hash(path)
    except Exception:
        return path, None

# --- Cache ---
def load_cache(root_dir):
    if not ENABLE_CACHE:
        return {}
    path = get_cache_path_for_root(root_dir)
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(root_dir, cache):
    if not ENABLE_CACHE:
        return
    path = get_cache_path_for_root(root_dir)
    tmp_path = Path(str(path) + ".tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(cache, f)
        os.replace(tmp_path, path)
    except Exception:
        pass

# --- FS utils ---
def list_all_files_with_stats(root_dir):
    files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            # Skip any local cache file name just in case (portable mode could add one)
            if os.path.basename(full) == ".duplicate_hash_cache.json":
                continue
            try:
                stat = os.stat(full)
                files.append((full, stat.st_size, int(stat.st_mtime)))
            except Exception:
                continue
    return files

def human_readable_size(size):
    if size >= 1024 ** 3:
        return f"{size / (1024 ** 3):.2f} GB"
    elif size >= 1024 ** 2:
        return f"{size / (1024 ** 2):.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size} B"

# --- Helpers for UI reuse ---
def sorted_duplicate_items(duplicates, group_sizes):
    # Sort duplicate groups by total size descending
    return sorted(
        duplicates.items(),
        key=lambda kv: group_sizes.get(kv[0], 0),
        reverse=True
    )

# --- Core duplicate finder with progress ---
def find_duplicates(root_dir):
    start = time.time()

    # load cache
    cache = load_cache(root_dir)
    cache_files = cache.get("files", {}) if cache else {}

    # list files
    all_files = list_all_files_with_stats(root_dir)
    total_files = len(all_files)
    print(f"📁 Scanning: {root_dir} — found {total_files} files", flush=True)

    # Group by size first
    size_groups = defaultdict(list)
    for path, size, mtime in all_files:
        size_groups[size].append((path, size, mtime))
    candidate_groups = [g for g in size_groups.values() if len(g) > 1]
    print(f"📏 Size-based candidate groups: {len(candidate_groups)}", flush=True)

    # Quick stage prep
    reused_cache_full = 0         # cache hits for full hash reuse
    quick_hashed = 0              # number of files actually quick-hashed this run
    full_hashed = 0               # number of files actually full-hashed this run
    quick_groups = defaultdict(list)

    # Build a list of everything that needs a quick hash (in one batch)
    all_need_quick = []

    for group in candidate_groups:
        for path, size, mtime in group:
            entry = cache_files.get(path)
            if (entry and entry.get("algo") == HASH_ALGORITHM and
                entry.get("size") == size and
                entry.get("mtime") == mtime and
                entry.get("quick_bytes") == QUICK_HASH_BYTES and
                "quick_hash" in entry):
                qh = entry["quick_hash"]
                quick_groups[(size, qh)].append((path, size, mtime, qh))
            else:
                all_need_quick.append((path, size, mtime))

    # Execute the quick hash stage in ONE pool
    if ENABLE_TWO_STAGE and all_need_quick:
        maxw = MAX_WORKERS or max(1, (os.cpu_count() or 2) - 1)
        Pool = ProcessPoolExecutor if USE_PROCESSES else ThreadPoolExecutor
        print(f"⚡ Quick hashing {len(all_need_quick)} files "
              f"using {'processes' if USE_PROCESSES else 'threads'} (workers={maxw})...",
              flush=True)

        start_quick = time.time()
        completed = 0
        with Pool(max_workers=maxw) as ex:
            futures = {ex.submit(compute_quick, p): (p, sz, mt) for (p, sz, mt) in all_need_quick}
            report_every = max(50, len(all_need_quick) // 100)  # ~1% or at least 50
            for fut in as_completed(futures):
                completed += 1
                path, sz, mt = futures[fut]
                pth, qh = fut.result()
                if qh:
                    quick_groups[(sz, qh)].append((pth, sz, mt, qh))
                    # update cache
                    entry = cache_files.get(pth, {})
                    entry.update({
                        "size": sz,
                        "mtime": mt,
                        "algo": HASH_ALGORITHM,
                        "quick_bytes": QUICK_HASH_BYTES,
                        "quick_hash": qh
                    })
                    cache_files[pth] = entry
                    quick_hashed += 1

                if completed % report_every == 0 or completed == len(all_need_quick):
                    elapsed = time.time() - start_quick
                    rate = completed / elapsed if elapsed else 0
                    remaining = len(all_need_quick) - completed
                    eta = remaining / rate if rate else float('inf')
                    print(f"  • Quick {completed}/{len(all_need_quick)} — ETA: {eta:.1f}s", flush=True)

    # Build list that needs full hashes (within each quick-group with len >= 2)
    to_full_hash = []
    for (size, qh), group in quick_groups.items():
        if len(group) < 2:
            continue
        for path, sz, mt, qh_val in group:
            entry = cache_files.get(path)
            if (entry and entry.get("algo") == HASH_ALGORITHM and
                entry.get("size") == sz and
                entry.get("mtime") == mt and
                "full_hash" in entry and
                (not ENABLE_TWO_STAGE or entry.get("quick_hash") == qh_val)):
                # We can reuse a cached full hash
                reused_cache_full += 1
            else:
                to_full_hash.append((path, sz, mt, qh_val))

    # Now, gather all re-usable full-hash entries into full_hash_map
    full_hash_map = defaultdict(list)
    # Add reused full hash entries
    for (size, qh), group in quick_groups.items():
        if len(group) < 2:
            continue
        for path, sz, mt, qh_val in group:
            entry = cache_files.get(path)
            if (entry and entry.get("algo") == HASH_ALGORITHM and
                entry.get("size") == sz and
                entry.get("mtime") == mt and
                "full_hash" in entry and
                (not ENABLE_TWO_STAGE or entry.get("quick_hash") == qh_val)):
                full_hash_map[entry["full_hash"]].append(path)

    # Full-hash stage with one pool + progress
    if to_full_hash:
        maxw = MAX_WORKERS or max(1, (os.cpu_count() or 2) - 1)
        print(f"🔍 Full hashing {len(to_full_hash)} files using processes (workers={maxw})...", flush=True)
        start_full = time.time()
        total = len(to_full_hash)
        completed = 0
        with ProcessPoolExecutor(max_workers=maxw) as ex:
            futures = {ex.submit(compute_full, p): (p, sz, mt, qh) for (p, sz, mt, qh) in to_full_hash}
            report_every = max(25, total // 100)  # ~1% or at least 25
            for fut in as_completed(futures):
                completed += 1
                elapsed = time.time() - start_full
                rate = completed / elapsed if elapsed else 0
                remaining = total - completed
                eta = remaining / rate if rate else float('inf')
                if completed % report_every == 0 or completed == total:
                    print(f"  • Full {completed}/{total} — ETA: {eta:.1f}s", flush=True)

                path, sz, mt, qh = futures[fut]
                pth, hval = fut.result()
                if hval:
                    full_hash_map[hval].append(path)
                    # Update cache with full hash
                    entry = cache_files.get(path, {})
                    entry.update({
                        "size": sz,
                        "mtime": mt,
                        "algo": HASH_ALGORITHM,
                        "full_hash": hval,
                        "quick_bytes": QUICK_HASH_BYTES if ENABLE_TWO_STAGE else None,
                        "quick_hash": qh if ENABLE_TWO_STAGE else entry.get("quick_hash")
                    })
                    cache_files[path] = entry
                    full_hashed += 1

    # Build duplicates dict (only keep groups with more than 1 file)
    duplicates = {h: paths for h, paths in full_hash_map.items() if len(paths) > 1}

    # Precompute group sizes once
    group_sizes = {}
    for h, paths in duplicates.items():
        total = 0
        for p in paths:
            try:
                total += os.path.getsize(p)
            except Exception:
                pass
        group_sizes[h] = total

    # Total duplicate size (sum of sizes of all files that are in duplicate sets)
    total_duplicate_size = sum(group_sizes.values())

    # Save cache
    if ENABLE_CACHE:
        save_cache(root_dir, {"files": cache_files, "algo": HASH_ALGORITHM, "generated_at": time.time()})

    stats = {
        "total_files": total_files,
        "candidate_size_groups": len(candidate_groups),
        "two_stage_quick_hashed": quick_hashed if ENABLE_TWO_STAGE else None,
        "full_hashed": full_hashed,
        "reused_cache": reused_cache_full,
        "duplicate_groups": len(duplicates),
        "elapsed_seconds": time.time() - start,
        "total_duplicate_size": total_duplicate_size
    }

    print("✅ Scan complete.", flush=True)
    return duplicates, stats, group_sizes

# --- UX helpers ---
def open_file_location(path):
    # Robust "open containing folder" with file selected where possible.
    try:
        if platform.system() == "Windows":
            p = os.path.normpath(path)
            try:
                subprocess.run(["explorer", "/select,", p], check=False)
            except Exception:
                subprocess.run(f'explorer /select,"{p}"', shell=True, check=False)
        elif platform.system() == "Darwin":
            subprocess.run(["open", "-R", path], check=False)
        else:
            folder = os.path.dirname(path) or "."
            try:
                subprocess.run(["xdg-open", folder], check=False)
            except FileNotFoundError:
                for fm in (["gio", "open", folder],
                           ["nautilus", folder],
                           ["dolphin", folder],
                           ["thunar", folder]):
                    try:
                        subprocess.Popen(fm)
                        break
                    except FileNotFoundError:
                        continue
    except Exception as e:
        print(f"[open_file_location] Failed for {path}: {e}", flush=True)

# --- Windows network drive helper ---
def _to_unc_if_network_drive(path):
    # Convert 'E:\\...' mapped network drive to UNC '\\\\server\\share\\...' when possible
    if platform.system() != "Windows":
        return path
    try:
        import ctypes
        from ctypes import wintypes, byref, create_string_buffer, cast, POINTER, c_void_p

        # Only drive-letter paths can be mapped drives
        p = os.path.abspath(path)
        if len(p) < 2 or p[1] != ":":
            return path

        WNetGetUniversalNameW = ctypes.windll.mpr.WNetGetUniversalNameW
        UNIVERSAL_NAME_INFO_LEVEL = 0x00000001  # UNIVERSAL_NAME_INFO
        ERROR_MORE_DATA = 234
        # First call to get required size
        size = wintypes.DWORD(0)
        res = WNetGetUniversalNameW(p, UNIVERSAL_NAME_INFO_LEVEL, None, byref(size))
        if res not in (0, ERROR_MORE_DATA):
            return path
        if size.value == 0:
            size.value = 2048
        buf = create_string_buffer(size.value)
        res = WNetGetUniversalNameW(p, UNIVERSAL_NAME_INFO_LEVEL, buf, byref(size))
        if res != 0:
            return path

        class UNIVERSAL_NAME_INFO(ctypes.Structure):
            _fields_ = [("lpUniversalName", wintypes.LPWSTR)]

        uni = cast(buf, POINTER(UNIVERSAL_NAME_INFO)).contents
        unc = uni.lpUniversalName
        return unc if unc else path
    except Exception:
        return path

def _trash_path_windows(p: str) -> bool:
    """
    Try to send to Recycle Bin on Windows.
    Falls back to UNC for mapped drives. Returns True on success, raises on error.
    """
    if send2trash is None:
        raise OSError("send2trash not installed")

    # Normalize to absolute & collapse oddities
    p_abs = os.path.abspath(os.path.normpath(p))

    try:
        send2trash(p_abs)
        return True
    except Exception as e:
        msg = str(e)
        # Retry with UNC if this looks like a mapped drive issue (Errno 3 / 'path specified')
        if ("[Errno 3]" in msg or "path specified" in msg) and len(p_abs) >= 3 and p_abs[1] == ":":
            unc = _to_unc_if_network_drive(p_abs)
            if unc and unc != p_abs:
                try:
                    send2trash(unc)
                    return True
                except Exception:
                    pass
        # Re-raise so caller can decide on permanent delete
        raise

# Selection/keep rule helpers
KEEP_RULES = ["Newest (keep most recent)", "Oldest (keep oldest)", "Alphabetical (keep A→Z)", "Shortest path"]

def choose_keep(files, rule_text):
    # returns the path to keep within this group
    if rule_text.startswith("Newest"):
        best = None; best_m = -1
        for p in files:
            try:
                m = os.stat(p).st_mtime
            except Exception:
                m = -1
            if m > best_m:
                best_m, best = m, p
        return best or files[0]
    if rule_text.startswith("Oldest"):
        best = None; best_m = 1e30
        for p in files:
            try:
                m = os.stat(p).st_mtime
            except Exception:
                m = 1e30
            if m < best_m:
                best_m, best = m, p
        return best or files[0]
    if rule_text.startswith("Alphabetical"):
        return sorted(files)[0]
    if rule_text.startswith("Shortest"):
        return sorted(files, key=lambda p: (len(p), p))[0]
    return files[0]

# --- UI ---
class DuplicateListWindow(QWidget):
    def __init__(self, duplicates, stats, root_dir, group_sizes):
        super().__init__()
        self.duplicates = duplicates
        self.stats = stats
        self.group_sizes = group_sizes
        self.root_dir = root_dir

        self.grid_mode = False
        self.selected = set()  # selected paths to delete
        self.checkboxes = {}    # path -> checkbox (list view)
        self.grid_checkboxes = {}  # path -> checkbox (grid view)

        self.setWindowTitle("🖼️ Duplicate File Gallery")
        self.setGeometry(120, 120, 1250, 820)

        self.main_layout = QVBoxLayout(self)

        title = QLabel(f"📂 Duplicate File Gallery — {root_dir}")
        # PyQt6: QFont.Weight exists; fallback keeps compatibility
        if hasattr(QFont, "Weight"):
            title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        else:
            title.setFont(QFont("Arial", 18))
        title.setWordWrap(True)
        self.main_layout.addWidget(title)

        # Summary lines
        summary = [
            f"📦 Total files scanned: {stats['total_files']}",
            f"📏 Size-based groups: {stats['candidate_size_groups']}",
            f"⚡ Quick hashed: {stats['two_stage_quick_hashed']}" if ENABLE_TWO_STAGE else "",
            f"🔍 Fully hashed: {stats['full_hashed']}",
            f"💾 Cache hits (full): {stats['reused_cache']}",
            f"🧠 Duplicate groups: {stats['duplicate_groups']}",
            f"🗑️ Total duplicate size: {human_readable_size(stats['total_duplicate_size'])}",
            f"⏱️ Elapsed time: {stats['elapsed_seconds']:.2f}s"
        ]
        stats_label = QLabel("\n".join([s for s in summary if s]))
        stats_label.setFont(QFont("Arial", 11))
        self.main_layout.addWidget(stats_label)

        # Controls: view toggle + deletion controls
        controls = QHBoxLayout()
        self.toggle_button = QPushButton("🔄 Toggle View")
        self.toggle_button.clicked.connect(self.toggle_view)
        controls.addWidget(self.toggle_button)

        controls.addWidget(QLabel("Keep rule:"))
        self.keep_combo = QComboBox()
        self.keep_combo.addItems(KEEP_RULES)
        controls.addWidget(self.keep_combo)

        self.auto_select_btn = QPushButton("✨ Auto-select deletions")
        self.auto_select_btn.clicked.connect(self.auto_select_deletions)
        controls.addWidget(self.auto_select_btn)

        self.clear_sel_btn = QPushButton("Clear selection")
        self.clear_sel_btn.clicked.connect(self.clear_selection)
        controls.addWidget(self.clear_sel_btn)

        self.delete_btn = QPushButton("🗑️ Send selected to Trash")
        self.delete_btn.clicked.connect(self.delete_selected)
        controls.addWidget(self.delete_btn)

        self.main_layout.addLayout(controls)

        # Stacked views
        self.stacked_layout = QStackedLayout()
        self.list_widget = self.create_list_view()
        self.grid_widget = None  # build lazily
        self.stacked_layout.addWidget(self.list_widget)
        self.main_layout.addLayout(self.stacked_layout)

    # --- Selection & Deletion logic ---
    def mark_selected(self, path, checked, origin="list"):
        if checked:
            self.selected.add(path)
        else:
            self.selected.discard(path)

        # keep checkboxes in sync across views
        cb = self.checkboxes.get(path)
        if cb and origin != "list":
            cb.blockSignals(True); cb.setChecked(checked); cb.blockSignals(False)
        gcb = self.grid_checkboxes.get(path)
        if gcb and origin != "grid":
            gcb.blockSignals(True); gcb.setChecked(checked); gcb.blockSignals(False)

    def auto_select_deletions(self):
        rule = self.keep_combo.currentText()
        sel_before = len(self.selected)
        for h, files in self.duplicates.items():
            if len(files) < 2:
                continue
            keep = choose_keep(files, rule)
            for p in files:
                want = (p != keep)
                self.mark_selected(p, want)
        delta = len(self.selected) - sel_before
        QMessageBox.information(self, "Auto-select", f"Selected {delta} files for deletion using rule:\n{rule}")

    def clear_selection(self):
        for p in list(self.selected):
            self.mark_selected(p, False)
        self.selected.clear()

    def _delete_paths(self, paths):
        errors = []
        deleted = []
        if not paths:
            return deleted, errors

        for p in paths:
            try:
                # Prefer Recycle Bin when available
                if platform.system() == "Windows" and send2trash is not None:
                    try:
                        if _trash_path_windows(p):
                            deleted.append(p); continue
                    except Exception as trash_err:
                        # If Trash fails on this item: offer one-time permanent delete
                        pretty = os.path.basename(p)
                        ret = QMessageBox.question(
                            self, "Trash unavailable — delete permanently?",
                            f"Windows couldn't move this file to the Recycle Bin:\n\n{pretty}\n\n"
                            f"Reason: {trash_err}\n\n"
                            f"Do you want to delete it permanently?",
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                        )
                        if ret == QMessageBox.StandardButton.Yes:
                            try:
                                os.remove(p)
                                deleted.append(p); continue
                            except Exception as e2:
                                errors.append((p, str(e2)))
                                continue
                        else:
                            # user declined — keep file and record the failure reason
                            errors.append((p, str(trash_err)))
                            continue

                # Non-Windows or no send2trash: ask once up front (you can wrap this with a global prompt if preferred)
                if send2trash is None or platform.system() != "Windows":
                    try:
                        if send2trash is not None and platform.system() != "Windows":
                            send2trash(p)
                        else:
                            os.remove(p)
                        deleted.append(p)
                        continue
                    except Exception as e:
                        errors.append((p, str(e)))
                        continue

            except Exception as e:
                errors.append((p, str(e)))

        return deleted, errors

    def delete_selected(self):
        if not self.selected:
            QMessageBox.information(self, "No selection", "No files are selected for deletion.")
            return
        total = 0
        for p in self.selected:
            try:
                total += os.path.getsize(p)
            except Exception:
                pass
        pretty = human_readable_size(total)
        ret = QMessageBox.question(
            self, "Confirm Deletion",
            f"Send {len(self.selected)} selected file(s) to Trash?\nApprox total size: {pretty}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if ret != QMessageBox.StandardButton.Yes:
            return

        to_delete = sorted(self.selected)
        deleted, errors = self._delete_paths(to_delete)

        if errors:
            msg = "\n".join([f"{p}: {e}" for p, e in errors][:10])
            QMessageBox.warning(self, "Some deletions failed", msg)

        if deleted:
            # Update in-memory structures
            self._apply_deletions(deleted)
            self.selected.difference_update(deleted)
            QMessageBox.information(self, "Deleted", f"Sent {len(deleted)} file(s) to Trash or removed permanently.")
            self.refresh_views()

    def delete_others_in_group(self, files):
        # Keep one based on combobox rule; delete the rest
        rule = self.keep_combo.currentText()
        keep = choose_keep(files, rule)
        victims = [p for p in files if p != keep]
        if not victims:
            QMessageBox.information(self, "Nothing to delete", "No other files to delete in this group.")
            return
        total = sum((os.path.getsize(p) if os.path.exists(p) else 0) for p in victims)
        ret = QMessageBox.question(
            self, "Confirm Deletion",
            f"Keep 1 ({os.path.basename(keep)}) and send {len(victims)} other file(s) to Trash?\n"
            f"Approx total size: {human_readable_size(total)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if ret != QMessageBox.StandardButton.Yes:
            return
        deleted, errors = self._delete_paths(victims)
        if errors:
            msg = "\n".join([f"{p}: {e}" for p, e in errors][:10])
            QMessageBox.warning(self, "Some deletions failed", msg)
        if deleted:
            self._apply_deletions(deleted)
            self.selected.difference_update(deleted)
            QMessageBox.information(self, "Deleted", f"Sent {len(deleted)} file(s) to Trash or removed permanently.")
            self.refresh_views()

    def _apply_deletions(self, deleted_paths):
        # Remove paths from duplicates; drop groups < 2; recompute group_sizes
        new_dups = {}
        for h, files in self.duplicates.items():
            remaining = [p for p in files if p not in deleted_paths and os.path.exists(p)]
            if len(remaining) >= 2:
                new_dups[h] = remaining
        self.duplicates = new_dups

        new_sizes = {}
        for h, files in self.duplicates.items():
            total = 0
            for p in files:
                try:
                    total += os.path.getsize(p)
                except Exception:
                    pass
            new_sizes[h] = total
        self.group_sizes = new_sizes

    # --- Views ---
    def toggle_view(self):
        self.grid_mode = not self.grid_mode
        if self.grid_mode:
            if self.grid_widget is None:
                self.grid_widget = self.create_grid_view()  # build on demand
                self.stacked_layout.addWidget(self.grid_widget)
            self.stacked_layout.setCurrentWidget(self.grid_widget)
        else:
            self.stacked_layout.setCurrentWidget(self.list_widget)

    def refresh_views(self):
        # Rebuild list view; if grid exists, drop & rebuild lazily again
        if self.list_widget:
            self.list_widget.setParent(None)
        self.checkboxes.clear()
        self.grid_checkboxes.clear()
        self.list_widget = self.create_list_view()
        # Reset stacked layout
        while self.stacked_layout.count():
            w = self.stacked_layout.widget(0)
            self.stacked_layout.removeWidget(w)
            w.setParent(None)
        self.grid_widget = None
        self.stacked_layout.addWidget(self.list_widget)
        self.grid_mode = False

    def create_list_view(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        vbox = QVBoxLayout(content)

        if not self.duplicates:
            vbox.addWidget(QLabel("✅ No duplicates found."))
        else:
            for h, files in sorted_duplicate_items(self.duplicates, self.group_sizes):
                total_size = self.group_sizes.get(h, 0)
                group_box = QGroupBox(f"🔷 {len(files)} Duplicates — {human_readable_size(total_size)}")
                group_layout = QGridLayout()

                # Per-group "Delete others" button (respects keep rule)
                del_others = QPushButton("Delete Others (keep 1)")
                del_others.clicked.connect(lambda _, fl=list(files): self.delete_others_in_group(fl))
                group_layout.addWidget(del_others, 0, 0, 1, 3)

                header = QLabel("<b>Files</b>")
                group_layout.addWidget(header, 0, 3)

                for idx, path in enumerate(sorted(files), start=1):
                    try:
                        size_text = human_readable_size(os.path.getsize(path))
                    except Exception:
                        size_text = "N/A"

                    cb = QCheckBox()
                    cb.setChecked(path in self.selected)
                    cb.stateChanged.connect(lambda state, p=path: self.mark_selected(p, state == Qt.CheckState.Checked, "list"))
                    self.checkboxes[path] = cb
                    group_layout.addWidget(cb, idx, 0)

                    file_label = QLabel(f"{os.path.basename(path)}\n{size_text}")
                    file_label.setWordWrap(True)
                    file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                    group_layout.addWidget(file_label, idx, 1, 1, 2)

                    open_button = QPushButton("Open in Folder")
                    open_button.clicked.connect(lambda _, p=path: open_file_location(p))
                    group_layout.addWidget(open_button, idx, 3)

                group_box.setLayout(group_layout)
                vbox.addWidget(group_box)

        scroll.setWidget(content)
        return scroll

    def create_grid_view(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        grid_layout = QGridLayout(content)

        if not self.duplicates:
            grid_layout.addWidget(QLabel("✅ No duplicates found."))
        else:
            col_count = 5
            row = col = 0

            for _, files in sorted_duplicate_items(self.duplicates, self.group_sizes):
                for path in sorted(files):
                    box = QGroupBox()
                    vbox = QVBoxLayout()

                    ext = os.path.splitext(path)[1].lower()
                    if ext in IMAGE_EXTENSIONS:
                        pixmap = QPixmap(path)
                        if not pixmap.isNull():
                            thumb = pixmap.scaled(180, 180, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                            image_label = QLabel()
                            image_label.setPixmap(thumb)
                            image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                            vbox.addWidget(image_label)
                        else:
                            fallback = QLabel("Image could not load")
                            fallback.setAlignment(Qt.AlignmentFlag.AlignCenter)
                            vbox.addWidget(fallback)
                    else:
                        try:
                            size_text = human_readable_size(os.path.getsize(path))
                        except Exception:
                            size_text = "N/A"
                        label = QLabel(f"{os.path.basename(path)}\n{size_text}")
                        label.setWordWrap(True)
                        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                        vbox.addWidget(label)

                    open_button = QPushButton("Open")
                    open_button.clicked.connect(lambda _, p=path: open_file_location(p))
                    vbox.addWidget(open_button)

                    cb = QCheckBox("Select")
                    cb.setChecked(path in self.selected)
                    cb.stateChanged.connect(lambda state, p=path: self.mark_selected(p, state == Qt.CheckState.Checked, "grid"))
                    self.grid_checkboxes[path] = cb
                    vbox.addWidget(cb)

                    box.setLayout(vbox)
                    box.setFixedSize(200, 270)
                    grid_layout.addWidget(box, row, col)
                    col += 1
                    if col >= col_count:
                        col = 0
                        row += 1

        scroll.setWidget(content)
        return scroll

# --- Background worker to keep UI responsive ---
class ScanWorker(QObject):
    finished = pyqtSignal(dict, dict, dict)  # duplicates, stats, group_sizes
    error = pyqtSignal(str)

    def __init__(self, root_dir):
        super().__init__()
        self.root_dir = root_dir

    def run(self):
        try:
            dups, stats, group_sizes = find_duplicates(self.root_dir)
            self.finished.emit(dups, stats, group_sizes)
        except Exception as e:
            self.error.emit(str(e))

# --- Main ---
def pick_or_cli_dir():
    if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
        return sys.argv[1]
    start_dir = os.path.expanduser("~")
    root_dir = QFileDialog.getExistingDirectory(None, "Select a folder to scan for duplicates", start_dir)
    return root_dir

def main():
    # Make stdout line-buffered so progress prints show up immediately.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    app = QApplication(sys.argv)

    root_dir = pick_or_cli_dir()
    if not root_dir:
        QMessageBox.information(None, "Duplicate File Gallery", "No folder selected. Exiting.")
        sys.exit(0)

    # Show a simple splash/progress window immediately
    splash = QWidget()
    splash.setWindowTitle("Duplicate File Gallery — Scanning...")
    vbox = QVBoxLayout(splash)
    msg = QLabel(f"Scanning {root_dir}...\nThis window will update when the scan completes.")
    msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
    msg.setFont(QFont("Arial", 12))
    vbox.addWidget(msg)
    splash.resize(520, 140)
    splash.show()

    # Start worker thread
    thread = QThread()
    worker = ScanWorker(root_dir)
    worker.moveToThread(thread)

    def on_finished(duplicates, stats, group_sizes):
        window = DuplicateListWindow(duplicates, stats, root_dir, group_sizes)
        window.show()
        splash.close()
        # Keep references alive
        app._main_window = window
        thread.quit()
        thread.wait()

    def on_error(err_msg):
        splash.close()
        QMessageBox.critical(None, "Scan Error", f"An error occurred during the scan:\n{err_msg}")
        thread.quit()
        thread.wait()
        sys.exit(2)

    thread.started.connect(worker.run)
    worker.finished.connect(on_finished)
    worker.error.connect(on_error)

    thread.start()
    sys.exit(app.exec())

if __name__ == "__main__":
    # Safe multiprocessing setup for Windows/macOS and PyInstaller
    import multiprocessing as mp
    if platform.system() in ("Windows", "Darwin"):
        mp.freeze_support()
        try:
            mp.set_start_method("spawn", force=True)
        except RuntimeError:
            pass

    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", flush=True)
        sys.exit(1)