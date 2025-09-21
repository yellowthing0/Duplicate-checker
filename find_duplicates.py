
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
    QPushButton, QGridLayout, QSizePolicy, QFileDialog, QMessageBox,
    QHBoxLayout, QCheckBox, QComboBox
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject

# Try to use system trash instead of permanent delete
try:
    from send2trash import send2trash
except Exception:
    send2trash = None

IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.bmp', '.gif')

# --- Config ---
HASH_ALGORITHM = "sha256"
USE_PROCESSES = True
ENABLE_CACHE = True
ENABLE_TWO_STAGE = True
QUICK_HASH_BYTES = 256 * 1024
MAX_WORKERS = None  # None -> auto (cpu_count - 1)

APP_NAME = "DuplicateGallery"
CACHE_ENV_VAR = "DUPGALLERY_CACHE_DIR"

def get_hash_function(algo):
    return {
        "sha256": hashlib.sha256,
        "md5": hashlib.md5,
        "blake2b": hashlib.blake2b
    }.get(algo.lower(), hashlib.sha256)

HASH_FUNC = get_hash_function(HASH_ALGORITHM)

def _user_cache_dir():
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
    hint = root_dir.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    h = hashlib.sha1(os.path.abspath(root_dir).encode("utf-8")).hexdigest()[:12]
    name = f"{hint}__{h}.json"
    return name[:180] if len(name) > 180 else name

def get_cache_path_for_root(root_dir: str) -> Path:
    d = _user_cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / _safe_name_from_root(root_dir)

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

def list_all_files_with_stats(root_dir):
    files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
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

def sorted_duplicate_items(duplicates, group_sizes):
    return sorted(
        duplicates.items(),
        key=lambda kv: group_sizes.get(kv[0], 0),
        reverse=True
    )

def find_duplicates(root_dir):
    start = time.time()
    cache = load_cache(root_dir)
    cache_files = cache.get("files", {}) if cache else {}

    all_files = list_all_files_with_stats(root_dir)
    total_files = len(all_files)
    print(f"📁 Scanning: {root_dir} — found {total_files} files", flush=True)

    size_groups = defaultdict(list)
    for path, size, mtime in all_files:
        size_groups[size].append((path, size, mtime))
    candidate_groups = [g for g in size_groups.values() if len(g) > 1]
    print(f"📏 Size-based candidate groups: {len(candidate_groups)}", flush=True)

    reused_cache_full = 0
    quick_hashed = 0
    full_hashed = 0
    quick_groups = defaultdict(list)

    all_need_quick = []
    for group in candidate_groups:
        for path, size, mtime in group:
            entry = cache_files.get(path)
            if (entry and entry.get("algo") == HASH_ALGORITHM and
                entry.get("size") == size and entry.get("mtime") == mtime and
                entry.get("quick_bytes") == QUICK_HASH_BYTES and "quick_hash" in entry):
                qh = entry["quick_hash"]
                quick_groups[(size, qh)].append((path, size, mtime, qh))
            else:
                all_need_quick.append((path, size, mtime))

    if ENABLE_TWO_STAGE and all_need_quick:
        maxw = MAX_WORKERS or max(1, (os.cpu_count() or 2) - 1)
        Pool = ProcessPoolExecutor if USE_PROCESSES else ThreadPoolExecutor
        print(f"⚡ Quick hashing {len(all_need_quick)} files using {'processes' if USE_PROCESSES else 'threads'} (workers={maxw})...", flush=True)
        with Pool(max_workers=maxw) as ex:
            futures = {ex.submit(compute_quick, p): (p, sz, mt) for (p, sz, mt) in all_need_quick}
            for fut in as_completed(futures):
                path, sz, mt = futures[fut]
                pth, qh = fut.result()
                if qh:
                    quick_groups[(sz, qh)].append((pth, sz, mt, qh))
                    entry = cache_files.get(pth, {})
                    entry.update({
                        "size": sz, "mtime": mt, "algo": HASH_ALGORITHM,
                        "quick_bytes": QUICK_HASH_BYTES, "quick_hash": qh
                    })
                    cache_files[pth] = entry
                    quick_hashed += 1

    to_full_hash = []
    for (size, qh), group in quick_groups.items():
        if len(group) < 2:
            continue
        for path, sz, mt, qh_val in group:
            entry = cache_files.get(path)
            if (entry and entry.get("algo") == HASH_ALGORITHM and
                entry.get("size") == sz and entry.get("mtime") == mt and
                "full_hash" in entry and (not ENABLE_TWO_STAGE or entry.get("quick_hash") == qh_val)):
                reused_cache_full += 1
            else:
                to_full_hash.append((path, sz, mt, qh_val))

    full_hash_map = defaultdict(list)
    for (size, qh), group in quick_groups.items():
        if len(group) < 2:
            continue
        for path, sz, mt, qh_val in group:
            entry = cache_files.get(path)
            if (entry and entry.get("algo") == HASH_ALGORITHM and
                entry.get("size") == sz and entry.get("mtime") == mt and "full_hash" in entry and
                (not ENABLE_TWO_STAGE or entry.get("quick_hash") == qh_val)):
                full_hash_map[entry["full_hash"]].append(path)

    if to_full_hash:
        maxw = MAX_WORKERS or max(1, (os.cpu_count() or 2) - 1)
        print(f"🔍 Full hashing {len(to_full_hash)} files using processes (workers={maxw})...", flush=True)
        with ProcessPoolExecutor(max_workers=maxw) as ex:
            futures = {ex.submit(compute_full, p): (p, sz, mt, qh) for (p, sz, mt, qh) in to_full_hash}
            for fut in as_completed(futures):
                path, sz, mt, qh = futures[fut]
                pth, hval = fut.result()
                if hval:
                    full_hash_map[hval].append(path)
                    entry = cache_files.get(path, {})
                    entry.update({
                        "size": sz, "mtime": mt, "algo": HASH_ALGORITHM,
                        "full_hash": hval, "quick_bytes": QUICK_HASH_BYTES if ENABLE_TWO_STAGE else None,
                        "quick_hash": qh if ENABLE_TWO_STAGE else entry.get("quick_hash")
                    })
                    cache_files[path] = entry
                    full_hashed += 1

    duplicates = {h: paths for h, paths in full_hash_map.items() if len(paths) > 1}

    # Precompute group total sizes and an individual size map
    group_sizes = {}
    file_sizes = {}
    for h, paths in duplicates.items():
        total = 0
        for p in paths:
            try:
                sz = os.path.getsize(p)
                file_sizes[p] = sz
                total += sz
            except Exception:
                file_sizes[p] = None
        group_sizes[h] = total

    total_duplicate_size = sum(group_sizes.values())
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
    return duplicates, stats, group_sizes, file_sizes

def open_file_location(path):
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
                for fm in (["gio", "open", folder], ["nautilus", folder], ["dolphin", folder], ["thunar", folder]):
                    try:
                        subprocess.Popen(fm)
                        break
                    except FileNotFoundError:
                        continue
    except Exception as e:
        print(f"[open_file_location] Failed for {path}: {e}", flush=True)

# Windows UNC helper
def _to_unc_if_network_drive(path):
    if platform.system() != "Windows":
        return path
    try:
        import ctypes
        from ctypes import wintypes, byref, create_string_buffer, cast, POINTER, c_void_p
        p = os.path.abspath(path)
        if len(p) < 2 or p[1] != ":":
            return path
        WNetGetUniversalNameW = ctypes.windll.mpr.WNetGetUniversalNameW
        UNIVERSAL_NAME_INFO_LEVEL = 0x00000001
        ERROR_MORE_DATA = 234
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
    if send2trash is None:
        raise OSError("send2trash not installed")
    p_abs = os.path.abspath(os.path.normpath(p))
    try:
        send2trash(p_abs)
        return True
    except Exception as e:
        msg = str(e)
        if ("[Errno 3]" in msg or "path specified" in msg) and len(p_abs) >= 3 and p_abs[1] == ":":
            unc = _to_unc_if_network_drive(p_abs)
            if unc and unc != p_abs:
                try:
                    send2trash(unc)
                    return True
                except Exception:
                    pass
        raise

KEEP_RULES = ["Newest (keep most recent)", "Oldest (keep oldest)", "Alphabetical (keep A→Z)", "Shortest path"]

def choose_keep(files, rule_text):
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

class GroupWidget(QGroupBox):
    def __init__(self, parent, hkey, files, group_size, file_sizes, on_open, on_check_changed, on_delete_others, is_checked):
        super().__init__(f"🔷 {len(files)} Duplicates — {human_readable_size(group_size)}")
        self.parent_ref = parent
        self.hkey = hkey
        self.files = list(sorted(files))
        self.file_sizes = file_sizes
        self.layout = QGridLayout()
        self.setLayout(self.layout)

        # Per-group delete-others
        del_others = QPushButton("Delete Others (keep 1)")
        del_others.clicked.connect(lambda: on_delete_others(self.files))
        self.layout.addWidget(del_others, 0, 0, 1, 3)

        header = QLabel("<b>Files</b>")
        self.layout.addWidget(header, 0, 3)

        self.checkboxes = {}
        self.rows = {}
        for idx, path in enumerate(self.files, start=1):
            cb = QCheckBox()
            cb.setChecked(is_checked(path))
            cb.stateChanged.connect(lambda state, p=path: on_check_changed(p, state == Qt.CheckState.Checked))
            self.checkboxes[path] = cb
            self.layout.addWidget(cb, idx, 0)

            sz = self.file_sizes.get(path)
            size_text = human_readable_size(sz) if isinstance(sz, int) else "N/A"
            file_label = QLabel(f"{os.path.basename(path)}\n{size_text}")
            file_label.setWordWrap(True)
            file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            self.layout.addWidget(file_label, idx, 1, 1, 2)

            btn = QPushButton("Open in Folder")
            btn.clicked.connect(lambda _, p=path: on_open(p))
            self.layout.addWidget(btn, idx, 3)

            self.rows[path] = (cb, file_label, btn)

    def remove_paths(self, paths_to_remove, new_group_size):
        """Remove rows for given paths; update header; return whether group still has >=2 files."""
        keep = []
        for p in self.files:
            if p in paths_to_remove:
                # remove row widgets
                widgets = self.rows.get(p)
                if widgets:
                    for w in widgets:
                        w.setParent(None)
                continue
            keep.append(p)
        self.files = keep
        self.setTitle(f"🔷 {len(self.files)} Duplicates — {human_readable_size(new_group_size)}")
        return len(self.files) >= 2

class DuplicateListWindow(QWidget):
    def __init__(self, duplicates, stats, root_dir, group_sizes, file_sizes):
        super().__init__()
        self.duplicates = duplicates
        self.stats = stats
        self.group_sizes = group_sizes
        self.file_sizes = file_sizes
        self.root_dir = root_dir

        self.selected = set()
        self.group_widgets = {}  # hash -> GroupWidget

        self.setWindowTitle("🖼️ Duplicate File Gallery")
        self.setGeometry(120, 120, 1100, 820)

        main_layout = QVBoxLayout(self)

        title = QLabel(f"📂 Duplicate File Gallery — {root_dir}")
        if hasattr(QFont, "Weight"):
            title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        else:
            title.setFont(QFont("Arial", 18))
        title.setWordWrap(True)
        main_layout.addWidget(title)

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
        main_layout.addWidget(stats_label)

        # Controls row
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Keep rule:"))
        self.keep_combo = QComboBox()
        self.keep_combo.addItems(KEEP_RULES)
        controls.addWidget(self.keep_combo)

        auto_btn = QPushButton("✨ Auto-select deletions")
        auto_btn.clicked.connect(self.auto_select_deletions)
        controls.addWidget(auto_btn)

        clear_btn = QPushButton("Clear selection")
        clear_btn.clicked.connect(self.clear_selection)
        controls.addWidget(clear_btn)

        del_btn = QPushButton("🗑️ Send selected to Trash")
        del_btn.clicked.connect(self.delete_selected)
        controls.addWidget(del_btn)

        controls.addStretch(1)
        main_layout.addLayout(controls)

        # Single list view
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll)

        self.build_groups()

    def build_groups(self):
        # Build group widgets once
        for h, files in sorted_duplicate_items(self.duplicates, self.group_sizes):
            gw = GroupWidget(
                parent=self,
                hkey=h,
                files=files,
                group_size=self.group_sizes.get(h, 0),
                file_sizes=self.file_sizes,
                on_open=open_file_location,
                on_check_changed=self.on_check_changed,
                on_delete_others=self.delete_others_in_group,
                is_checked=lambda p: p in self.selected
            )
            self.group_widgets[h] = gw
            self.scroll_layout.addWidget(gw)

        if not self.group_widgets:
            self.scroll_layout.addWidget(QLabel("✅ No duplicates found."))

    # Selection helpers
    def on_check_changed(self, path, checked):
        if checked:
            self.selected.add(path)
        else:
            self.selected.discard(path)

    def auto_select_deletions(self):
        rule = self.keep_combo.currentText()
        added = 0
        for h, files in self.duplicates.items():
            if len(files) < 2: continue
            keep = choose_keep(files, rule)
            for p in files:
                if p != keep and p not in self.selected:
                    self.selected.add(p)
                    # reflect in UI
                    gw = self.group_widgets.get(h)
                    if gw and p in gw.checkboxes:
                        cb = gw.checkboxes[p]
                        cb.blockSignals(True); cb.setChecked(True); cb.blockSignals(False)
                        added += 1
        QMessageBox.information(self, "Auto-select", f"Selected {added} file(s) for deletion.")

    def clear_selection(self):
        # Efficiently uncheck without rebuilding UI
        for h, gw in self.group_widgets.items():
            for p, cb in gw.checkboxes.items():
                if p in self.selected:
                    cb.blockSignals(True); cb.setChecked(False); cb.blockSignals(False)
        self.selected.clear()

    # Deletion logic
    def _delete_paths(self, paths):
        errors = []
        deleted = []
        for p in paths:
            try:
                if platform.system() == "Windows" and send2trash is not None:
                    try:
                        if _trash_path_windows(p):
                            deleted.append(p); continue
                    except Exception as trash_err:
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
                                os.remove(p); deleted.append(p); continue
                            except Exception as e2:
                                errors.append((p, str(e2))); continue
                        else:
                            errors.append((p, str(trash_err))); continue
                # Non-Windows or no send2trash
                if send2trash is not None and platform.system() != "Windows":
                    send2trash(p); deleted.append(p)
                else:
                    os.remove(p); deleted.append(p)
            except Exception as e:
                errors.append((p, str(e)))
        return deleted, errors

    def delete_selected(self):
        if not self.selected:
            QMessageBox.information(self, "No selection", "No files are selected for deletion.")
            return
        total = sum((self.file_sizes.get(p) or 0) for p in self.selected)
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
            self.apply_deletions(deleted)
            QMessageBox.information(self, "Deleted", f"Deleted/trashed {len(deleted)} file(s).")

    def delete_others_in_group(self, files):
        rule = self.keep_combo.currentText()
        keep = choose_keep(files, rule)
        victims = [p for p in files if p != keep]
        if not victims:
            QMessageBox.information(self, "Nothing to delete", "No other files to delete in this group.")
            return
        total = sum((self.file_sizes.get(p) or 0) for p in victims)
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
            self.apply_deletions(deleted)
            QMessageBox.information(self, "Deleted", f"Deleted/trashed {len(deleted)} file(s).")

    def apply_deletions(self, deleted_paths):
        # Update models
        self.setUpdatesEnabled(False)
        deleted_set = set(deleted_paths)
        # Remove from selection
        self.selected.difference_update(deleted_set)

        # Update duplicates mapping and group sizes
        to_remove_groups = []
        for h, files in list(self.duplicates.items()):
            if not files: continue
            remaining = [p for p in files if p not in deleted_set and os.path.exists(p)]
            if len(remaining) < 2:
                to_remove_groups.append(h)
            else:
                self.duplicates[h] = remaining
                # recompute group size efficiently
                gtotal = 0
                for p in remaining:
                    if p in self.file_sizes and self.file_sizes[p] is not None:
                        gtotal += self.file_sizes[p]
                    else:
                        try:
                            sz = os.path.getsize(p)
                            self.file_sizes[p] = sz
                            gtotal += sz
                        except Exception:
                            self.file_sizes[p] = None
                self.group_sizes[h] = gtotal

        # Update UI widgets per group
        for h, gw in list(self.group_widgets.items()):
            if h in to_remove_groups:
                # remove whole group
                gw.setParent(None)
                del self.group_widgets[h]
                if h in self.duplicates: del self.duplicates[h]
                if h in self.group_sizes: del self.group_sizes[h]
            else:
                # update rows
                if h in self.duplicates:
                    still_has = gw.remove_paths(deleted_set, self.group_sizes.get(h, 0))
                    if not still_has:
                        gw.setParent(None)
                        del self.group_widgets[h]
                        del self.duplicates[h]
                        if h in self.group_sizes: del self.group_sizes[h]

        self.setUpdatesEnabled(True)

class ScanWorker(QObject):
    finished = pyqtSignal(dict, dict, dict, dict)
    error = pyqtSignal(str)

    def __init__(self, root_dir):
        super().__init__()
        self.root_dir = root_dir

    def run(self):
        try:
            dups, stats, group_sizes, file_sizes = find_duplicates(self.root_dir)
            self.finished.emit(dups, stats, group_sizes, file_sizes)
        except Exception as e:
            self.error.emit(str(e))

def pick_or_cli_dir():
    if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
        return sys.argv[1]
    start_dir = os.path.expanduser("~")
    root_dir = QFileDialog.getExistingDirectory(None, "Select a folder to scan for duplicates", start_dir)
    return root_dir

def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    app = QApplication(sys.argv)

    root_dir = pick_or_cli_dir()
    if not root_dir:
        QMessageBox.information(None, "Duplicate File Gallery", "No folder selected. Exiting.")
        sys.exit(0)

    # Simple splash while scanning
    splash = QWidget()
    splash.setWindowTitle("Duplicate File Gallery — Scanning...")
    vbox = QVBoxLayout(splash)
    msg = QLabel(f"Scanning {root_dir}...\nThis window will update when the scan completes.")
    msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
    msg.setFont(QFont("Arial", 12))
    vbox.addWidget(msg)
    splash.resize(520, 140)
    splash.show()

    thread = QThread()
    worker = ScanWorker(root_dir)
    worker.moveToThread(thread)

    def on_finished(duplicates, stats, group_sizes, file_sizes):
        window = DuplicateListWindow(duplicates, stats, root_dir, group_sizes, file_sizes)
        window.show()
        splash.close()
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
