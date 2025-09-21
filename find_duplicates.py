
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
    QPushButton, QGridLayout, QSizePolicy, QStackedLayout, QFileDialog, QMessageBox
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject

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
def group_total_size(paths):
    total = 0
    for p in paths:
        try:
            total += os.path.getsize(p)
        except Exception:
            pass
    return total

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
            # First try standard argument list
            try:
                subprocess.run(["explorer", "/select,", p], check=False)
            except Exception:
                # Fallback: shell string with quotes
                subprocess.run(f'explorer /select,"{p}"', shell=True, check=False)
        elif platform.system() == "Darwin":
            subprocess.run(["open", "-R", path], check=False)
        else:
            # Linux: try xdg-open on the directory; fall back to common FMs
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

# --- UI ---
class DuplicateListWindow(QWidget):
    def __init__(self, duplicates, stats, root_dir, group_sizes):
        super().__init__()
        self.duplicates = duplicates
        self.stats = stats
        self.group_sizes = group_sizes
        self.grid_mode = False

        self.setWindowTitle("🖼️ Duplicate File Gallery")
        self.setGeometry(200, 200, 1200, 800)

        self.main_layout = QVBoxLayout(self)

        title = QLabel(f"📂 Duplicate File Gallery — {root_dir}")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
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
        stats_label = QLabel("\n".join(filter(None, summary)))
        stats_label.setFont(QFont("Arial", 11))
        self.main_layout.addWidget(stats_label)

        self.toggle_button = QPushButton("🔄 Toggle View")
        self.toggle_button.clicked.connect(self.toggle_view)
        self.main_layout.addWidget(self.toggle_button)

        self.stacked_layout = QStackedLayout()
        self.list_widget = self.create_list_view()
        self.grid_widget = None  # build lazily
        self.stacked_layout.addWidget(self.list_widget)

        self.main_layout.addLayout(self.stacked_layout)

    def toggle_view(self):
        self.grid_mode = not self.grid_mode
        if self.grid_mode:
            if self.grid_widget is None:
                self.grid_widget = self.create_grid_view()  # build on demand
                self.stacked_layout.addWidget(self.grid_widget)
            self.stacked_layout.setCurrentWidget(self.grid_widget)
        else:
            self.stacked_layout.setCurrentWidget(self.list_widget)

    def create_list_view(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        if not self.duplicates:
            scroll_layout.addWidget(QLabel("✅ No duplicates found."))
        else:
            for h, files in sorted_duplicate_items(self.duplicates, self.group_sizes):
                total_size = self.group_sizes.get(h, 0)
                group_box = QGroupBox(f"🔷 {len(files)} Duplicates — {human_readable_size(total_size)}")
                group_layout = QGridLayout()

                for i, path in enumerate(sorted(files)):
                    try:
                        size_text = human_readable_size(os.path.getsize(path))
                    except Exception:
                        size_text = "N/A"

                    file_label = QLabel(f"{os.path.basename(path)}\n{size_text}")
                    file_label.setWordWrap(True)
                    file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

                    open_button = QPushButton("Open in Folder")
                    open_button.clicked.connect(lambda _, p=path: open_file_location(p))

                    group_layout.addWidget(file_label, i, 0)
                    group_layout.addWidget(open_button, i, 1)

                group_box.setLayout(group_layout)
                scroll_layout.addWidget(group_box)

        scroll.setWidget(scroll_content)
        return scroll

    def create_grid_view(self):
        # Build the grid only when the user toggles to it
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        grid_layout = QGridLayout(scroll_content)

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
                            thumbnail = pixmap.scaled(180, 180, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                            image_label = QLabel()
                            image_label.setPixmap(thumbnail)
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

                    box.setLayout(vbox)
                    box.setFixedSize(200, 250)
                    grid_layout.addWidget(box, row, col)
                    col += 1
                    if col >= col_count:
                        col = 0
                        row += 1

        scroll.setWidget(scroll_content)
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
        # Build the main window now, quickly (grid view is lazy)
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
