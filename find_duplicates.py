#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import hashlib
import platform
import subprocess
from pathlib import Path
from collections import defaultdict
from concurrent.futures import (
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    wait,
    FIRST_COMPLETED,
)

from threading import Event

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QScrollArea, QGroupBox,
    QPushButton, QGridLayout, QSizePolicy, QFileDialog, QMessageBox,
    QHBoxLayout, QCheckBox, QComboBox, QProgressBar, QSpacerItem
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject

# Optional: send to OS recycle bin / trash
try:
    from send2trash import send2trash
except Exception:
    send2trash = None


IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".gif")

# ==========================
# Configuration
# ==========================

APP_NAME = "DuplicateGallery"
CACHE_ENV_VAR = "DUPGALLERY_CACHE_DIR"

# Hashing
HASH_ALGORITHM = "sha256"
HASH_FUNC_MAP = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
    "blake2b": hashlib.blake2b,
}
HASH_FUNC = HASH_FUNC_MAP.get(HASH_ALGORITHM, hashlib.sha256)

ENABLE_TWO_STAGE = True

# Head+tail quick hash window
QUICK_HASH_BYTES = 64 * 1024

# Skip tiny files (speeds up huge scans; tweak as you like)
MIN_SIZE_BYTES = 64 * 1024  # 64 KiB

# Concurrency (tuned for HDD by default)
MAX_WORKERS = None  # None -> cpu_count - 1
USE_THREADS_FOR_QUICK = True         # quick stage = I/O-bound
USE_PROCESSES_FOR_FULL = True        # full stage = CPU-bound

INFLIGHT_FACTOR = 2                  # in-flight quick jobs per worker
FULL_INFLIGHT_FACTOR = 1             # in-flight full jobs per worker

# Cache
ENABLE_CACHE = True

# Safety
WORKER_TIMEOUT_SECONDS = 15.0

# Checkpoint: flush cache to disk every N hash updates
CHECKPOINT_EVERY = 10_000


# ==========================
# Cache paths
# ==========================

def _user_cache_dir() -> Path:
    """Centralized per-user cache root, overridable by env var."""
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
    """Build a readable + stable cache filename for a scanned root."""
    hint = (
        root_dir
        .replace(":", "")
        .replace("\\", "_")
        .replace("/", "_")
        .strip("_")
    )
    h = hashlib.sha1(os.path.abspath(root_dir).encode("utf-8")).hexdigest()[:12]
    name = f"{hint}__{h}.json"
    return name[:180] if len(name) > 180 else name


def get_cache_path_for_root(root_dir: str) -> Path:
    d = _user_cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / _safe_name_from_root(root_dir)


# ==========================
# Hash helpers
# ==========================

def get_hash_function(name: str):
    return HASH_FUNC_MAP.get(name.lower(), hashlib.sha256)


HASH_FUNC = get_hash_function(HASH_ALGORITHM)


def full_file_hash(path: str, block_size: int = 4 * 1024 * 1024) -> str:
    h = HASH_FUNC()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()


def quick_file_hash(path: str, first_n: int = QUICK_HASH_BYTES) -> str:
    """
    Head + tail hash:
    - read first N bytes
    - read last N bytes (if file is large enough)
    """
    h = HASH_FUNC()
    with open(path, "rb") as f:
        head = f.read(first_n)
        h.update(head)
        try:
            f.seek(-first_n, os.SEEK_END)
            tail = f.read(first_n)
            h.update(tail)
        except Exception:
            # very small file, only head available
            pass
    return h.hexdigest()


def compute_quick(path: str):
    try:
        if not os.path.exists(path):
            return path, None
        return path, quick_file_hash(path)
    except Exception:
        return path, None


def compute_full(path: str):
    try:
        if not os.path.exists(path):
            return path, None
        return path, full_file_hash(path)
    except Exception:
        return path, None


# ==========================
# Cache I/O (JSON)
# ==========================

def load_cache(root_dir: str) -> dict:
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


def save_cache(root_dir: str, cache: dict):
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


# ==========================
# Misc helpers
# ==========================

def human_readable_size(size: int) -> str:
    if size >= 1024 ** 3:
        return f"{size / (1024 ** 3):.2f} GB"
    elif size >= 1024 ** 2:
        return f"{size / (1024 ** 2):.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size} B"


def check_pause(pause_event: Event | None, stop_event: Event | None):
    """Cooperative pause/cancel point."""
    if stop_event is not None and stop_event.is_set():
        raise RuntimeError("Scan cancelled")
    if pause_event is not None and pause_event.is_set():
        while pause_event.is_set():
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError("Scan cancelled")
            time.sleep(0.1)


# ==========================
# FS utils
# ==========================

def list_all_files_with_stats(root_dir: str, progress_cb=None,
                              pause_event: Event | None = None,
                              stop_event: Event | None = None):
    files = []
    last_emit = 0.0
    for dirpath, _, filenames in os.walk(root_dir):
        check_pause(pause_event, stop_event)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            # skip tiny cache file name from older versions
            if os.path.basename(full) == ".duplicate_hash_cache.json":
                continue
            try:
                stat = os.stat(full)
            except Exception:
                continue

            if stat.st_size < MIN_SIZE_BYTES:
                continue

            files.append((full, stat.st_size, int(stat.st_mtime)))

            now = time.time()
            if progress_cb and (now - last_emit) > 0.25:
                last_emit = now
                progress_cb(
                    "listing",
                    len(files),
                    0,
                    None,
                    f"Listing files… ({len(files)} found)"
                )
    return files


# ==========================
# Bounded submission helper
# ==========================

def bounded_submit(executor, func, items_iter, max_inflight: int,
                   progress_tick=None,
                   pause_event: Event | None = None,
                   stop_event: Event | None = None):
    """
    Yield futures as they complete while keeping at most `max_inflight` tasks
    in flight. Uses wait(FIRST_COMPLETED) to avoid TimeoutError storms.
    Cooperates with pause/stop.
    """
    inflight = set()
    items = iter(items_iter)

    # Prime queue
    try:
        for _ in range(max_inflight):
            item = next(items)
            fut = executor.submit(func, item)
            setattr(fut, "_payload", item)
            inflight.add(fut)
    except StopIteration:
        pass

    last_tick = time.time()
    while inflight:
        check_pause(pause_event, stop_event)

        done, not_done = wait(
            inflight,
            timeout=0.5,
            return_when=FIRST_COMPLETED
        )
        inflight = not_done

        for fut in done:
            yield fut

        # Refill
        try:
            while len(inflight) < max_inflight:
                item = next(items)
                fut = executor.submit(func, item)
                setattr(fut, "_payload", item)
                inflight.add(fut)
        except StopIteration:
            pass

        if progress_tick and (time.time() - last_tick) > 0.25:
            last_tick = time.time()
            progress_tick()


# ==========================
# Open file location
# ==========================

def open_file_location(path: str):
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
            subprocess.run(["xdg-open", folder], check=False)
    except Exception as e:
        print(f"[open_file_location] Failed for {path}: {e}", flush=True)


# ==========================
# Duplicate finder core
# ==========================

def sorted_duplicate_items(duplicates: dict, group_sizes: dict):
    return sorted(
        duplicates.items(),
        key=lambda kv: group_sizes.get(kv[0], 0),
        reverse=True,
    )


def find_duplicates(root_dir: str,
                    progress_cb=None,
                    pause_event: Event | None = None,
                    stop_event: Event | None = None):
    """
    Main pipeline with cache, two-stage hashing, bounded concurrency,
    and cooperative pause/cancel.
    """
    start = time.time()
    if progress_cb:
        progress_cb("init", 0, 0, None, "Preparing…")

    cache = load_cache(root_dir)
    cache_files = cache.get("files", {}) if cache else {}

    # 1) List files
    if progress_cb:
        progress_cb("listing", 0, 0, None, "Listing files…")

    all_files = list_all_files_with_stats(
        root_dir,
        progress_cb=progress_cb,
        pause_event=pause_event,
        stop_event=stop_event,
    )
    total_files = len(all_files)

    if progress_cb:
        progress_cb(
            "listing_done",
            total_files,
            total_files,
            None,
            f"Found {total_files} files (≥ {human_readable_size(MIN_SIZE_BYTES)})"
        )

    print(f"📁 Scanning: {root_dir} — found {total_files} files", flush=True)

    # Group by size
    size_groups = defaultdict(list)
    for path, size, mtime in all_files:
        size_groups[size].append((path, size, mtime))
    candidate_groups = [g for g in size_groups.values() if len(g) > 1]
    print(f"📏 Size-based candidate groups: {len(candidate_groups)}", flush=True)

    reused_cache_full = 0
    quick_hashed = 0
    full_hashed = 0
    quick_groups = defaultdict(list)

    # Prepare quick hash worklist
    all_need_quick = []
    for group in candidate_groups:
        for path, size, mtime in group:
            entry = cache_files.get(path)
            if (
                entry and entry.get("algo") == HASH_ALGORITHM
                and entry.get("size") == size
                and entry.get("mtime") == mtime
                and entry.get("quick_bytes") == QUICK_HASH_BYTES
                and "quick_hash" in entry
            ):
                qh = entry["quick_hash"]
                quick_groups[(size, qh)].append((path, size, mtime, qh))
            else:
                all_need_quick.append((path, size, mtime))

    # 2) Quick hash stage
    if ENABLE_TWO_STAGE and all_need_quick:
        maxw = MAX_WORKERS or max(1, (os.cpu_count() or 2) - 1)
        total_quick = len(all_need_quick)
        since_checkpoint = 0

        if progress_cb:
            progress_cb(
                "quick", 0, total_quick, None,
                f"Quick hashing {total_quick} file(s)…"
            )

        meta_quick = {p: (sz, mt) for (p, sz, mt) in all_need_quick}
        Executor = ThreadPoolExecutor if USE_THREADS_FOR_QUICK else ProcessPoolExecutor

        with Executor(max_workers=maxw) as ex:
            completed = 0
            max_inflight = max(1, maxw * INFLIGHT_FACTOR)

            def tick():
                if progress_cb:
                    progress_cb(
                        "quick",
                        completed,
                        total_quick,
                        None,
                        f"Quick hashing… {completed}/{total_quick}"
                    )

            items_iter = (p for (p, _, _) in all_need_quick)
            for fut in bounded_submit(
                ex,
                compute_quick,
                items_iter,
                max_inflight,
                tick,
                pause_event=pause_event,
                stop_event=stop_event,
            ):
                check_pause(pause_event, stop_event)
                pth = getattr(fut, "_payload", None)
                try:
                    result = fut.result(timeout=WORKER_TIMEOUT_SECONDS)
                except Exception as e:
                    print(f"[WARN] Quick worker failed on {pth}: {e}", flush=True)
                    continue

                completed += 1
                pth2, qh = result

                if qh:
                    sz, mt = meta_quick.get(pth2, (None, None))
                    if sz is None:
                        try:
                            st = os.stat(pth2)
                            sz, mt = st.st_size, int(st.st_mtime)
                        except Exception:
                            sz, mt = 0, 0

                    quick_groups[(sz, qh)].append((pth2, sz, mt, qh))

                    entry = cache_files.get(pth2, {})
                    entry.update(
                        {
                            "size": sz,
                            "mtime": mt,
                            "algo": HASH_ALGORITHM,
                            "quick_bytes": QUICK_HASH_BYTES,
                            "quick_hash": qh,
                        }
                    )
                    cache_files[pth2] = entry
                    quick_hashed += 1
                    since_checkpoint += 1

                    if (
                        ENABLE_CACHE
                        and since_checkpoint >= CHECKPOINT_EVERY
                    ):
                        save_cache(
                            root_dir,
                            {
                                "files": cache_files,
                                "algo": HASH_ALGORITHM,
                                "generated_at": time.time(),
                            },
                        )
                        since_checkpoint = 0

                if progress_cb and (
                    completed % 2048 == 0 or completed == total_quick
                ):
                    progress_cb(
                        "quick",
                        completed,
                        total_quick,
                        None,
                        f"Quick hashing… {completed}/{total_quick}",
                    )

    # 3) Decide which need full hashes (with basename sub-bucket)
    to_full_hash = []
    for (size, qh), group in quick_groups.items():
        if len(group) < 2:
            continue

        # Sub-bucket by filename to avoid hashing obviously different files
        buckets = defaultdict(list)
        for path, sz, mt, qh_val in group:
            buckets[os.path.basename(path)].append((path, sz, mt, qh_val))

        for _, bucket in buckets.items():
            if len(bucket) < 2:
                continue
            for path, sz, mt, qh_val in bucket:
                entry = cache_files.get(path)
                if (
                    entry
                    and entry.get("algo") == HASH_ALGORITHM
                    and entry.get("size") == sz
                    and entry.get("mtime") == mt
                    and "full_hash" in entry
                    and (not ENABLE_TWO_STAGE or entry.get("quick_hash") == qh_val)
                ):
                    reused_cache_full += 1
                else:
                    to_full_hash.append((path, sz, mt, qh_val))

    full_hash_map = defaultdict(list)

    # Add reused full-hash entries into the map (with basename buckets too)
    for (size, qh), group in quick_groups.items():
        if len(group) < 2:
            continue
        buckets = defaultdict(list)
        for path, sz, mt, qh_val in group:
            buckets[os.path.basename(path)].append((path, sz, mt, qh_val))

        for _, bucket in buckets.items():
            if len(bucket) < 2:
                continue
            for path, sz, mt, qh_val in bucket:
                entry = cache_files.get(path)
                if (
                    entry
                    and entry.get("algo") == HASH_ALGORITHM
                    and entry.get("size") == sz
                    and entry.get("mtime") == mt
                    and "full_hash" in entry
                    and (not ENABLE_TWO_STAGE or entry.get("quick_hash") == qh_val)
                ):
                    full_hash_map[entry["full_hash"]].append(path)

    # 4) Full-hash stage
    if to_full_hash:
        maxw = MAX_WORKERS or max(1, (os.cpu_count() or 2) - 1)
        total_full = len(to_full_hash)
        since_checkpoint = 0

        if progress_cb:
            progress_cb(
                "full",
                0,
                total_full,
                None,
                f"Full hashing {total_full} file(s)…",
            )

        meta_full = {p: (sz, mt, qh) for (p, sz, mt, qh) in to_full_hash}
        Executor = ProcessPoolExecutor if USE_PROCESSES_FOR_FULL else ThreadPoolExecutor

        with Executor(max_workers=maxw) as ex:
            completed = 0
            max_inflight = max(1, maxw * FULL_INFLIGHT_FACTOR)

            def tick():
                if progress_cb:
                    progress_cb(
                        "full",
                        completed,
                        total_full,
                        None,
                        f"Full hashing… {completed}/{total_full}",
                    )

            items_iter = (p for (p, _, _, _) in to_full_hash)
            for fut in bounded_submit(
                ex,
                compute_full,
                items_iter,
                max_inflight,
                tick,
                pause_event=pause_event,
                stop_event=stop_event,
            ):
                check_pause(pause_event, stop_event)

                pth = getattr(fut, "_payload", None)
                try:
                    result = fut.result(timeout=WORKER_TIMEOUT_SECONDS)
                except Exception as e:
                    print(f"[WARN] Full worker failed on {pth}: {e}", flush=True)
                    continue

                completed += 1
                pth2, hval = result
                if hval:
                    full_hash_map[hval].append(pth2)
                    sz, mt, qh = meta_full.get(pth2, (None, None, None))
                    entry = cache_files.get(pth2, {})
                    entry.update(
                        {
                            "size": sz,
                            "mtime": mt,
                            "algo": HASH_ALGORITHM,
                            "full_hash": hval,
                            "quick_bytes": QUICK_HASH_BYTES
                            if ENABLE_TWO_STAGE
                            else None,
                            "quick_hash": qh
                            if ENABLE_TWO_STAGE
                            else entry.get("quick_hash"),
                        }
                    )
                    cache_files[pth2] = entry
                    full_hashed += 1
                    since_checkpoint += 1

                    if (
                        ENABLE_CACHE
                        and since_checkpoint >= CHECKPOINT_EVERY
                    ):
                        save_cache(
                            root_dir,
                            {
                                "files": cache_files,
                                "algo": HASH_ALGORITHM,
                                "generated_at": time.time(),
                            },
                        )
                        since_checkpoint = 0

                if progress_cb and (
                    completed % 512 == 0 or completed == total_full
                ):
                    progress_cb(
                        "full",
                        completed,
                        total_full,
                        None,
                        f"Full hashing… {completed}/{total_full}",
                    )

    # 5) Build duplicates dict
    duplicates = {h: paths for h, paths in full_hash_map.items() if len(paths) > 1}

    # Precompute sizes
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

    files_listed = sum(len(paths) for paths in duplicates.values())
    total_duplicate_size = sum(group_sizes.values())

    if ENABLE_CACHE:
        save_cache(
            root_dir,
            {
                "files": cache_files,
                "algo": HASH_ALGORITHM,
                "generated_at": time.time(),
            },
        )

    stats = {
        "total_files": total_files,
        "candidate_size_groups": len(candidate_groups),
        "two_stage_quick_hashed": quick_hashed if ENABLE_TWO_STAGE else None,
        "full_hashed": full_hashed,
        "reused_cache": reused_cache_full,
        "duplicate_groups": len(duplicates),
        "elapsed_seconds": time.time() - start,
        "total_duplicate_size": total_duplicate_size,
        "files_listed": files_listed,
    }

    if progress_cb:
        progress_cb("done", 1, 1, None, "Finalizing…")

    print("✅ Scan complete.", flush=True)
    return duplicates, stats, group_sizes, file_sizes


# ==========================
# UI components
# ==========================

KEEP_RULES = [
    "Newest (keep most recent)",
    "Oldest (keep oldest)",
    "Alphabetical (keep A→Z)",
    "Shortest path",
]


def choose_keep(files, rule_text):
    if rule_text.startswith("Newest"):
        best = None
        best_m = -1
        for p in files:
            try:
                m = os.stat(p).st_mtime
            except Exception:
                m = -1
            if m > best_m:
                best_m, best = m, p
        return best or files[0]
    if rule_text.startswith("Oldest"):
        best = None
        best_m = 1e30
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
    """
    One duplicate group with per-file checkboxes and actions.
    """

    def __init__(
        self,
        parent,
        hkey,
        files,
        group_size,
        file_sizes,
        on_open,
        on_check_changed,
        on_delete_others,
        is_checked,
    ):
        super().__init__(
            f"🔷 {len(files)} Duplicates — {human_readable_size(group_size)}"
        )
        self.parent_ref = parent
        self.hkey = hkey
        self.files = list(sorted(files))
        self.file_sizes = file_sizes

        self.layout = QGridLayout()
        self.setLayout(self.layout)

        # Per-group action: delete all but chosen
        del_others = QPushButton("Delete Others (keep 1)")
        del_others.clicked.connect(lambda: on_delete_others(self.files))
        self.layout.addWidget(del_others, 0, 0, 1, 4)

        header = QLabel("<b>Files</b>")
        self.layout.addWidget(header, 0, 4)

        self.checkboxes = {}
        self.rows = {}

        for idx, path in enumerate(self.files, start=1):
            cb = QCheckBox()
            cb.setChecked(is_checked(path))
            cb.stateChanged.connect(
                lambda state, p=path: on_check_changed(
                    p, state == Qt.CheckState.Checked
                )
            )
            self.checkboxes[path] = cb
            self.layout.addWidget(cb, idx, 0)

            sz = self.file_sizes.get(path)
            size_text = (
                human_readable_size(sz)
                if isinstance(sz, int)
                else "N/A"
            )
            name = os.path.basename(path)
            dirp = os.path.dirname(path)

            file_label = QLabel(
                f"<b>{name}</b><br>"
                f"<span style='color:gray'>{dirp}</span><br>"
                f"{size_text}"
            )
            file_label.setTextFormat(Qt.TextFormat.RichText)
            file_label.setWordWrap(True)
            file_label.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,
            )
            self.layout.addWidget(file_label, idx, 1, 1, 3)

            btn_open = QPushButton("Open")
            btn_open.clicked.connect(lambda _, p=path: on_open(p))
            self.layout.addWidget(btn_open, idx, 4)

            btn_copy = QPushButton("Copy path")
            btn_copy.clicked.connect(
                lambda _, p=path: QApplication.clipboard().setText(p)
            )
            self.layout.addWidget(btn_copy, idx, 5)

            self.rows[path] = (cb, file_label, btn_open, btn_copy)

    def remove_paths(self, paths_to_remove, new_group_size):
        """Remove rows for deleted paths; return True if group still has ≥2."""
        keep = []
        for p in self.files:
            if p in paths_to_remove:
                widgets = self.rows.get(p)
                if widgets:
                    for w in widgets:
                        w.setParent(None)
                continue
            keep.append(p)
        self.files = keep
        self.setTitle(
            f"🔷 {len(self.files)} Duplicates — {human_readable_size(new_group_size)}"
        )
        return len(self.files) >= 2


class DuplicateListWindow(QWidget):
    """
    Main results window with controls and duplicate groups.
    """

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
        self.setGeometry(120, 120, 1200, 820)

        main_layout = QVBoxLayout(self)

        title = QLabel(f"📂 Duplicate File Gallery — {root_dir}")
        if hasattr(QFont, "Weight"):
            title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        else:
            title.setFont(QFont("Arial", 18))
        title.setWordWrap(True)
        main_layout.addWidget(title)

        self.stats_label = QLabel()
        self.stats_label.setFont(QFont("Arial", 11))
        main_layout.addWidget(self.stats_label)

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

        # Scroll area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll)

        self.empty_label = QLabel("✅ No duplicates found.")
        self.empty_label.setVisible(False)
        self.scroll_layout.addWidget(self.empty_label)

        self.build_groups()
        self.refresh_summary_label()

    def build_groups(self):
        has_any = False
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
                is_checked=lambda p: p in self.selected,
            )
            self.group_widgets[h] = gw
            self.scroll_layout.addWidget(gw)
            has_any = True
        self.empty_label.setVisible(not has_any)

    def gather_checked_paths(self) -> set:
        checked = set()
        for gw in self.group_widgets.values():
            for p, cb in gw.checkboxes.items():
                if cb.isChecked():
                    checked.add(p)
        return checked

    def on_check_changed(self, path, checked):
        if checked:
            self.selected.add(path)
        else:
            self.selected.discard(path)

    def auto_select_deletions(self):
        rule = self.keep_combo.currentText()
        added = 0
        self.selected = self.gather_checked_paths()

        for h, files in self.duplicates.items():
            if len(files) < 2:
                continue
            keep = choose_keep(files, rule)
            gw = self.group_widgets.get(h)
            if not gw:
                continue
            for p in files:
                want_checked = p != keep
                cb = gw.checkboxes.get(p)
                if cb and cb.isChecked() != want_checked:
                    cb.blockSignals(True)
                    cb.setChecked(want_checked)
                    cb.blockSignals(False)
                if want_checked and p not in self.selected:
                    self.selected.add(p)
                    added += 1
                elif not want_checked and p in self.selected:
                    self.selected.discard(p)

        QMessageBox.information(
            self,
            "Auto-select",
            f"Selected {added} file(s) for deletion.",
        )

    def clear_selection(self):
        for gw in self.group_widgets.values():
            for _, cb in gw.checkboxes.items():
                if cb.isChecked():
                    cb.blockSignals(True)
                    cb.setChecked(False)
                    cb.blockSignals(False)
        self.selected.clear()

    def _delete_paths(self, paths):
        import errno

        errors = []
        deleted = []

        for p in paths:
            norm = os.path.normpath(p)

            try:
                if send2trash is not None:
                    send2trash(norm)
                else:
                    os.remove(norm)
                deleted.append(norm)

            except OSError as e:
                # Errno 3 (ENOENT) -> treat as already gone, not a hard failure
                if e.errno == errno.ENOENT:
                    deleted.append(norm)
                else:
                    errors.append((norm, str(e)))

            except Exception as e:
                errors.append((norm, str(e)))

        return deleted, errors


    def delete_selected(self):
        self.selected = self.gather_checked_paths()
        if not self.selected:
            QMessageBox.information(
                self,
                "No selection",
                "No files are selected for deletion.",
            )
            return

        total = sum((self.file_sizes.get(p) or 0) for p in self.selected)
        pretty = human_readable_size(total)
        ret = QMessageBox.question(
            self,
            "Confirm Deletion",
            (
                f"Send {len(self.selected)} selected file(s) to Trash?\n"
                f"Approx total size: {pretty}"
            ),
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
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
            QMessageBox.information(
                self,
                "Deleted",
                f"Deleted/trashed {len(deleted)} file(s).",
            )

    def delete_others_in_group(self, files):
        rule = self.keep_combo.currentText()
        keep = choose_keep(files, rule)
        victims = [p for p in files if p != keep]
        if not victims:
            QMessageBox.information(
                self,
                "Nothing to delete",
                "No other files to delete in this group.",
            )
            return

        total = sum((self.file_sizes.get(p) or 0) for p in victims)
        pretty = human_readable_size(total)
        ret = QMessageBox.question(
            self,
            "Confirm Deletion",
            (
                f"Keep 1 ({os.path.basename(keep)}) and send "
                f"{len(victims)} other file(s) to Trash?\n"
                f"Approx total size: {pretty}"
            ),
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
        )
        if ret != QMessageBox.StandardButton.Yes:
            return

        deleted, errors = self._delete_paths(victims)

        if errors:
            msg = "\n".join([f"{p}: {e}" for p, e in errors][:10])
            QMessageBox.warning(self, "Some deletions failed", msg)

        if deleted:
            self.apply_deletions(deleted)
            QMessageBox.information(
                self,
                "Deleted",
                f"Deleted/trashed {len(deleted)} file(s).",
            )

    def apply_deletions(self, deleted_paths):
        self.setUpdatesEnabled(False)
        deleted_set = set(deleted_paths)
        self.selected.difference_update(deleted_set)

        to_remove_groups = []

        # Update internal structures
        for h, files in list(self.duplicates.items()):
            if not files:
                continue
            remaining = [
                p for p in files if p not in deleted_set and os.path.exists(p)
            ]
            if len(remaining) < 2:
                to_remove_groups.append(h)
            else:
                self.duplicates[h] = remaining
                gtotal = 0
                for p in remaining:
                    sz = self.file_sizes.get(p)
                    if not isinstance(sz, int):
                        try:
                            sz = os.path.getsize(p)
                            self.file_sizes[p] = sz
                        except Exception:
                            sz = 0
                            self.file_sizes[p] = None
                    gtotal += sz
                self.group_sizes[h] = gtotal

        # Update UI widgets
        for h, gw in list(self.group_widgets.items()):
            if h in to_remove_groups:
                gw.setParent(None)
                del self.group_widgets[h]
                if h in self.duplicates:
                    del self.duplicates[h]
                if h in self.group_sizes:
                    del self.group_sizes[h]
            else:
                if h in self.duplicates:
                    still_has = gw.remove_paths(
                        deleted_set, self.group_sizes.get(h, 0)
                    )
                    if not still_has:
                        gw.setParent(None)
                        del self.group_widgets[h]
                        if h in self.duplicates:
                            del self.duplicates[h]
                        if h in self.group_sizes:
                            del self.group_sizes[h]

        self.empty_label.setVisible(len(self.group_widgets) == 0)

        self.setUpdatesEnabled(True)
        self.refresh_summary_label()

    def refresh_summary_label(self):
        files_listed = sum(len(v) for v in self.duplicates.values())
        duplicate_groups = len(self.duplicates)
        total_duplicate_size = sum(
            self.group_sizes.get(h, 0) for h in self.duplicates.keys()
        )

        self.stats["files_listed"] = files_listed
        self.stats["duplicate_groups"] = duplicate_groups
        self.stats["total_duplicate_size"] = total_duplicate_size

        summary = [
            f"📦 Total files scanned: {self.stats['total_files']}",
            f"📏 Size-based groups: {self.stats['candidate_size_groups']}",
            (
                f"⚡ Quick hashed: {self.stats['two_stage_quick_hashed']}"
                if ENABLE_TWO_STAGE
                else ""
            ),
            f"🔍 Fully hashed: {self.stats['full_hashed']}",
            f"💾 Cache hits (full): {self.stats['reused_cache']}",
            f"🧠 Duplicate groups: {duplicate_groups}",
            f"🧾 Files listed: {files_listed}",
            f"🗑️ Total duplicate size: {human_readable_size(total_duplicate_size)}",
            f"⏱️ Elapsed time: {self.stats['elapsed_seconds']:.2f}s",
        ]
        self.stats_label.setText("\n".join([s for s in summary if s]))


# ==========================
# Worker + progress UI
# ==========================

class ScanWorker(QObject):
    finished = pyqtSignal(dict, dict, dict, dict)  # duplicates, stats, group_sizes, file_sizes
    error = pyqtSignal(str)
    progress = pyqtSignal(str, int, int, float, str)

    def __init__(self, root_dir: str):
        super().__init__()
        self.root_dir = root_dir
        self.pause_event = Event()
        self.stop_event = Event()

    def pause(self):
        self.pause_event.set()

    def resume(self):
        self.pause_event.clear()

    def cancel(self):
        self.stop_event.set()

    def run(self):
        try:
            def cb(stage, current, total, eta, message):
                self.progress.emit(stage, int(current or 0), int(total or 0), -1.0, message or "")

            dups, stats, group_sizes, file_sizes = find_duplicates(
                self.root_dir,
                progress_cb=cb,
                pause_event=self.pause_event,
                stop_event=self.stop_event,
            )
            self.finished.emit(dups, stats, group_sizes, file_sizes)
        except Exception as e:
            self.error.emit(str(e))


def pick_or_cli_dir():
    if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
        return sys.argv[1]
    start_dir = os.path.expanduser("~")
    return QFileDialog.getExistingDirectory(
        None,
        "Select a folder to scan for duplicates",
        start_dir,
    )


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    app = QApplication(sys.argv)

    root_dir = pick_or_cli_dir()
    if not root_dir:
        QMessageBox.information(
            None,
            "Duplicate File Gallery",
            "No folder selected. Exiting.",
        )
        sys.exit(0)

    # --- Scanning splash window ---
    splash = QWidget(
        flags=Qt.WindowType.Window
        | Qt.WindowType.CustomizeWindowHint
        | Qt.WindowType.WindowTitleHint
    )
    splash.setWindowTitle("Duplicate File Gallery — Scanning…")

    vwrap = QVBoxLayout(splash)
    vwrap.setContentsMargins(24, 18, 24, 18)

    vwrap.addItem(
        QSpacerItem(
            0,
            10,
            QSizePolicy.Policy.Minimum,
            QSizePolicy.Policy.Expanding,
        )
    )

    center = QWidget()
    center_layout = QVBoxLayout(center)
    center_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    center.setMaximumWidth(640)

    head = QLabel(f"Scanning {root_dir}")
    head.setAlignment(Qt.AlignmentFlag.AlignCenter)
    head.setFont(QFont("Arial", 12))

    status = QLabel("Preparing…")
    status.setAlignment(Qt.AlignmentFlag.AlignCenter)

    bar = QProgressBar()
    bar.setFixedWidth(520)
    bar.setRange(0, 0)  # indeterminate initially

    percent_label = QLabel("")
    percent_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

    center_layout.addWidget(head, alignment=Qt.AlignmentFlag.AlignHCenter)
    center_layout.addWidget(status, alignment=Qt.AlignmentFlag.AlignHCenter)
    center_layout.addWidget(bar, alignment=Qt.AlignmentFlag.AlignHCenter)
    center_layout.addWidget(percent_label, alignment=Qt.AlignmentFlag.AlignHCenter)

    # Pause / Resume buttons
    controls_layout = QHBoxLayout()
    controls_layout.addStretch(1)
    pause_btn = QPushButton("Pause")
    resume_btn = QPushButton("Resume")
    controls_layout.addWidget(pause_btn)
    controls_layout.addWidget(resume_btn)
    controls_layout.addStretch(1)
    center_layout.addLayout(controls_layout)

    vwrap.addWidget(center, alignment=Qt.AlignmentFlag.AlignHCenter)
    vwrap.addItem(
        QSpacerItem(
            0,
            10,
            QSizePolicy.Policy.Minimum,
            QSizePolicy.Policy.Expanding,
        )
    )

    splash.resize(800, 240)
    splash.show()

    # Worker in a thread
    thread = QThread()
    worker = ScanWorker(root_dir)
    worker.moveToThread(thread)

    def on_progress(stage, current, total, _eta, message):
        status.setText(message)
        if stage in ("quick", "full"):
            if total > 0:
                if bar.maximum() != total:
                    bar.setRange(0, total)
                bar.setValue(current)
                percent = (current / total) * 100 if total else 0
                percent_label.setText(f"{current:,}/{total:,}  ({percent:.0f}%)")
            else:
                bar.setRange(0, 0)
                percent_label.setText("")
        elif stage in ("listing", "listing_done"):
            if stage == "listing_done":
                bar.setRange(0, 1)
                bar.setValue(1)
                percent_label.setText("")
            else:
                bar.setRange(0, 0)
                percent_label.setText("")
        elif stage == "done":
            bar.setRange(0, 1)
            bar.setValue(1)
            percent_label.setText("")

    def on_finished(duplicates, stats, group_sizes, file_sizes):
        window = DuplicateListWindow(duplicates, stats, root_dir, group_sizes, file_sizes)
        window.show()
        splash.close()
        # keep reference
        app._main_window = window
        thread.quit()
        thread.wait()

    def on_error(err_msg):
        splash.close()
        QMessageBox.critical(
            None,
            "Scan Error",
            f"An error occurred during the scan:\n{err_msg}",
        )
        thread.quit()
        thread.wait()
        sys.exit(2)

    thread.started.connect(worker.run)
    worker.progress.connect(on_progress)
    worker.finished.connect(on_finished)
    worker.error.connect(on_error)

    pause_btn.clicked.connect(worker.pause)
    resume_btn.clicked.connect(worker.resume)

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
