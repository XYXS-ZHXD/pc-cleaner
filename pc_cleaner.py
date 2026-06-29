#!/usr/bin/env python3
"""
PC清理助手 v1.3.0
Windows系统盘垃圾扫描与安全清理工具
专为电脑小白设计 - 安全第一，操作简单

目标扫描策略：只扫描预定义的高概率垃圾路径（靶点扫描），不遍历全盘。
安全原则：删除到回收站，WinSxS/System32等白名单目录永不触碰。
"""

import os
import sys
import time
import ctypes
import threading
import subprocess
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================
# Constants
# ============================================================

APP_NAME = "PC清理助手"
VERSION = "1.3.0"
APP_TITLE = f"{APP_NAME} v{VERSION}"

# Colors for risk levels
COLOR_SAFE = "#2E7D32"      # Green
COLOR_CAUTIOUS = "#E65100"  # Orange
COLOR_INFO = "#1565C0"       # Blue
COLOR_BG_SAFE = "#E8F5E9"
COLOR_BG_CAUTIOUS = "#FFF3E0"
COLOR_BG_INFO = "#E3F2FD"
COLOR_WARNING_BG = "#FFF9C4"
COLOR_WARNING_FG = "#F57F17"

# ============================================================
# Whitelist - directories never touched
# ============================================================

WHITELIST_PATHS = [
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "WinSxS"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Boot"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "servicing"),
    os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files")),
    os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")),
    os.path.join(os.environ.get("ProgramData", "C:\\ProgramData")),
]

def is_whitelisted(path):
    """Check if path is under any whitelisted directory."""
    norm_path = os.path.normpath(path).lower()
    for wp in WHITELIST_PATHS:
        if wp and norm_path.startswith(os.path.normpath(wp).lower()):
            return True
    return False

# ============================================================
# Scan Targets - predefined high-probability junk paths
# ============================================================

def get_user_local():
    return os.environ.get("LOCALAPPDATA", 
        os.path.expanduser("~\\AppData\\Local"))

def get_system_root():
    return os.environ.get("SystemRoot", "C:\\Windows")

USER_TEMP = os.environ.get("TEMP", os.path.expanduser("~\\AppData\\Local\\Temp"))
SYS_ROOT = get_system_root()
USER_LOCAL = get_user_local()

SCAN_TARGETS = [
    # === SAFE targets ===
    {"name": "用户临时文件", "path": USER_TEMP, "level": "safe",
     "desc": "系统和软件产生的临时文件，可安全删除"},
    {"name": "系统临时文件", "path": os.path.join(SYS_ROOT, "Temp"), "level": "safe",
     "desc": "Windows系统临时目录，需管理员权限"},
    {"name": "预读缓存(Prefetch)", "path": os.path.join(SYS_ROOT, "Prefetch"), "level": "safe",
     "desc": "加快程序启动的缓存，删除后首次启动稍慢，可自动重建"},
    {"name": "Windows更新下载", "path": os.path.join(SYS_ROOT, "SoftwareDistribution", "Download"),
     "level": "safe", "desc": "已安装的Windows更新包，删除不影响已安装的更新"},

    # Chrome Browser Caches
    {"name": "Chrome浏览器缓存", "path": os.path.join(USER_LOCAL, "Google", "Chrome", "User Data", "Default", "Cache"),
     "level": "safe", "desc": "Chrome网页缓存文件"},
    {"name": "Chrome代码缓存", "path": os.path.join(USER_LOCAL, "Google", "Chrome", "User Data", "Default", "Code Cache"),
     "level": "safe", "desc": "Chrome JavaScript代码缓存"},

    # Edge Browser Caches
    {"name": "Edge浏览器缓存", "path": os.path.join(USER_LOCAL, "Microsoft", "Edge", "User Data", "Default", "Cache"),
     "level": "safe", "desc": "Edge网页缓存文件"},
    {"name": "Edge代码缓存", "path": os.path.join(USER_LOCAL, "Microsoft", "Edge", "User Data", "Default", "Code Cache"),
     "level": "safe", "desc": "Edge JavaScript代码缓存"},

    # Firefox
    {"name": "Firefox缓存", "path": os.path.join(USER_LOCAL, "Mozilla", "Firefox", "Profiles"),
     "level": "safe", "desc": "Firefox浏览器缓存目录（只清理cache2子目录）",
     "subdir": "cache2"},

    # Delivery Optimization cache
    {"name": "传递优化文件", "path": os.path.join(SYS_ROOT, "ServiceState", "EventLog"),
     "level": "safe", "desc": "Windows更新传递优化缓存"},
    {"name": "传递优化缓存", "path": os.path.join(SYS_ROOT, "SoftwareDistribution", "DeliveryOptimization"),
     "level": "safe", "desc": "Windows更新分发优化文件"},

    # Crash dumps (cautious)
    {"name": "系统崩溃转储", "path": os.path.join(SYS_ROOT, "Minidump"), "level": "cautious",
     "desc": "蓝屏时产生的小型转储文件，分析完可删除"},
    {"name": "系统内存转储", "path": os.path.join(SYS_ROOT, "MEMORY.DMP"), "level": "cautious",
     "desc": "蓝屏时产生的大内存转储文件，通常几百MB到几GB"},
    {"name": "用户错误报告", "path": os.path.join(USER_LOCAL, "CrashDumps"), "level": "cautious",
     "desc": "程序崩溃时产生的转储文件"},

    # Windows.old (cautious - after major Win updates)
    {"name": "Windows旧版本备份", "path": os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Windows.old"),
     "level": "cautious", "desc": "系统大版本升级后的旧系统备份，如果新系统稳定即可删除"},

    # Various logs (cautious)
    {"name": "Windows日志", "path": os.path.join(SYS_ROOT, "Logs"), "level": "cautious",
     "desc": "系统和应用程序日志，一般占用不大"},
    {"name": "Windows CBS日志", "path": os.path.join(SYS_ROOT, "Logs", "CBS"), "level": "cautious",
     "desc": "Windows更新日志，可安全清理"},
]

# ============================================================
# Utility Functions
# ============================================================

def is_admin():
    """Check if the program is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def format_size(bytes_val):
    """Format byte count to human-readable string."""
    if bytes_val <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(bytes_val)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    if i == 0:
        return f"{int(size)} B"
    return f"{size:.1f} {units[i]}"

def get_dir_size(path, depth=2, timeout=3.0):
    """
    Get directory size with depth and time limits.
    Returns (size_in_bytes, accessible: bool)
    """
    if not os.path.exists(path):
        return 0, False
    
    total = 0
    start_time = time.time()
    
    try:
        if os.path.isfile(path):
            return os.path.getsize(path), True
        
        # For directories, walk with depth limit
        for root, dirs, files in os.walk(path):
            if time.time() - start_time > timeout:
                break
            
            rel_depth = root[len(path):].count(os.sep)
            if rel_depth >= depth:
                dirs[:] = []
                continue
            
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except PermissionError:
        return total if total > 0 else -1, False
    except OSError:
        return total if total > 0 else -1, False
    
    return total, True

def get_dir_size_fast(path, timeout=5.0, _depth=0):
    """
    Fast directory size scan - only check first level subdirectories.
    For large folders, stop after timeout.
    Hard limit: max 3 levels of recursion depth.
    Returns (size, is_accessible, is_approximate)
    """
    if _depth > 3:
        return 0, True, True  # Too deep, approximate
    
    if not os.path.exists(path):
        return 0, False, False
    
    if os.path.isfile(path):
        try:
            return os.path.getsize(path), True, False
        except OSError:
            return 0, False, False
    
    total = 0
    approx = False
    start_time = time.time()
    
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if time.time() - start_time > timeout:
                    approx = True
                    break
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat().st_size
                    elif entry.is_dir(follow_symlinks=False):
                        # Only scan first level of each subdirectory
                        sub_size, _, _ = get_dir_size_fast(entry.path, timeout=timeout, _depth=_depth+1)
                        total += sub_size
                except (PermissionError, OSError):
                    pass
    except PermissionError:
        return -1 if total == 0 else total, False, approx
    except OSError:
        return 0, False, approx
    
    return total, True, approx

# ============================================================
# File Deletion Engine — multi-strategy:
#   1. Send to Recycle Bin (recoverable)
#   2. Remove read-only, retry Recycle Bin
#   3. Mark for reboot-delete (locked files)
# ============================================================

# MoveFileEx constants
MOVEFILE_DELAY_UNTIL_REBOOT = 0x0004

# SHFileOperation constants
FO_DELETE = 3
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0002


def send_to_recycle_bin(filepath, parent_hwnd=None):
    """
    Send a file or directory to the Recycle Bin using Windows Shell API.
    Returns True on success.
    """
    try:
        path_abs = os.path.abspath(filepath)
        # Double-null-terminated wide string (required by SHFileOperationW)
        buf = (ctypes.c_wchar * (len(path_abs) + 2))()
        for i, ch in enumerate(path_abs):
            buf[i] = ch
        buf[len(path_abs)] = '\0'
        buf[len(path_abs) + 1] = '\0'

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", ctypes.c_void_p),
                ("wFunc", ctypes.c_uint),
                ("pFrom", ctypes.c_wchar_p),
                ("pTo", ctypes.c_wchar_p),
                ("fFlags", ctypes.c_uint16),
                ("fAnyOperationsAborted", ctypes.c_int),
                ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", ctypes.c_wchar_p),
            ]

        fileop = SHFILEOPSTRUCTW()
        fileop.hwnd = parent_hwnd or 0
        fileop.wFunc = FO_DELETE
        fileop.pFrom = ctypes.cast(ctypes.pointer(buf), ctypes.c_wchar_p)
        fileop.pTo = None
        fileop.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        fileop.fAnyOperationsAborted = 0
        fileop.hNameMappings = None
        fileop.lpszProgressTitle = None

        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(fileop))
        return result == 0
    except Exception:
        return False


def mark_for_reboot_delete(filepath):
    """Schedule a file for deletion on next system reboot (for locked files)."""
    try:
        path_abs = os.path.abspath(filepath)
        if not ctypes.windll.kernel32.MoveFileExW(path_abs, None, MOVEFILE_DELAY_UNTIL_REBOOT):
            return False
        return True
    except Exception:
        return False


def delete_file(filepath):
    """
    Try to delete a single file. Strategies in order:
    1. Send to Recycle Bin (recoverable via Shell API)
    2. Remove read-only attribute, retry Recycle Bin
    3. MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) — mark for reboot
    Returns ("recycled" | "reboot" | "skipped", reason_string)
    """
    if not os.path.exists(filepath):
        return "recycled", ""

    path_abs = os.path.abspath(filepath)

    # Strategy 1: Send to Recycle Bin (recoverable!)
    if send_to_recycle_bin(path_abs):
        return "recycled", ""

    # Strategy 2: remove read-only attribute, retry
    try:
        os.chmod(path_abs, 0o777)
        if send_to_recycle_bin(path_abs):
            return "recycled", ""
    except (PermissionError, OSError):
        pass

    # Strategy 3: mark for deletion on reboot
    if mark_for_reboot_delete(path_abs):
        return "reboot", ""

    return "skipped", "文件被占用且无法标记重启删除"

def delete_empty_dir(dirpath):
    """Try to remove an empty directory. Returns True on success."""
    if not os.path.isdir(dirpath):
        return True
    try:
        os.rmdir(dirpath)
        return True
    except OSError:
        # Directory not empty or locked — that's fine
        return False

def clean_directory_contents(dirpath, progress_callback=None):
    """
    Clean CONTENTS of a directory — walk through all files/subdirs bottom-up,
    delete each using direct-delete strategy.
    NEVER deletes the top-level directory itself.
    
    Returns (deleted_count, reboot_count, failed_count, freed_bytes, errors_list).
    """
    if not os.path.isdir(dirpath):
        return 0, 0, 0, 0, []
    
    deleted = 0
    reboot = 0
    failed = 0
    freed = 0
    errors = []
    
    # Gather all items bottom-up (files first, then dirs)
    all_items = []
    try:
        for root, dirs, files in os.walk(dirpath, topdown=False):
            for f in files:
                all_items.append(("file", os.path.join(root, f)))
            for d in dirs:
                all_items.append(("dir", os.path.join(root, d)))
    except PermissionError:
        pass
    
    total = len(all_items)
    if total > 5000:
        errors.append(f"[限制] 目录包含{total}个项目，仅处理前5000个")
        all_items = all_items[:5000]
        total = 5000
    
    for i, (item_type, item_path) in enumerate(all_items):
        if progress_callback and total > 0:
            progress_callback(i + 1, total, os.path.basename(item_path))
        
        if not os.path.exists(item_path):
            continue
        
        try:
            size_before = 0
            if item_type == "file":
                try:
                    size_before = os.path.getsize(item_path)
                except OSError:
                    pass
                
                result, reason = delete_file(item_path)
                if result == "recycled" or result == "deleted":
                    deleted += 1
                    freed += size_before
                elif result == "reboot":
                    reboot += 1
                    freed += size_before
                else:
                    failed += 1
                    if len(errors) < 30:
                        errors.append(f"[跳过] {item_path} — {reason}")
            else:  # directory
                delete_empty_dir(item_path)
                # Don't count dirs in stats
        except Exception as e:
            failed += 1
            if len(errors) < 30:
                errors.append(f"[错误] {item_path}: {e}")
    
    return deleted, reboot, failed, freed, errors

def open_disk_cleanup():
    """Open Windows Disk Cleanup tool. User can manually select items to clean."""
    try:
        subprocess.Popen(["cleanmgr", "/d", os.environ.get("SystemDrive", "C:")])
        return True
    except Exception:
        return False


# ============================================================
# Scanner Engine
# ============================================================

class ScanEngine:
    """Background scanner that finds junk files and top folders."""
    
    def __init__(self):
        self.results = []           # List of scan result dicts
        self.top_folders = []       # Top 10 largest folders
        self.scanning = False
        
    def scan_folder_size(self, path, depth=2, timeout=3.0):
        """Quick scan a single folder's size."""
        if not os.path.exists(path):
            return -1
        return get_dir_size(path, depth=depth, timeout=timeout)[0]
    
    def scan_targets(self, progress_callback=None):
        """Scan all predefined targets for junk files."""
        self.results = []
        
        for i, target in enumerate(SCAN_TARGETS):
            path = target["path"]
            if not path or not os.path.exists(path):
                if progress_callback:
                    progress_callback(i + 1, len(SCAN_TARGETS), target["name"])
                continue
            
            # For Firefox, handle profile subdirectories
            if "subdir" in target:
                try:
                    total_size = 0
                    for item in os.scandir(path):
                        sub_path = os.path.join(item.path, target["subdir"])
                        if os.path.exists(sub_path):
                            size, _ = get_dir_size(sub_path, depth=2, timeout=3.0)
                            if size > 0:
                                total_size += size
                except (PermissionError, OSError):
                    total_size = -1
            else:
                if os.path.isfile(path):
                    try:
                        total_size = os.path.getsize(path)
                    except OSError:
                        total_size = -1
                else:
                    size, accessible = get_dir_size(path, depth=2, timeout=3.0)
                    total_size = size if accessible else -1
            
            if total_size > 0:
                result = {
                    "name": target["name"],
                    "path": path,
                    "size": total_size,
                    "level": target["level"],
                    "desc": target["desc"],
                    "checked": target["level"] == "safe",  # Safe items checked by default
                }
                self.results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, len(SCAN_TARGETS), target["name"])
    
    def scan_top_folders(self, progress_callback=None):
        """Find the top 10 largest folders on C: drive (targeted scan)."""
        self.top_folders = []
        system_drive = os.environ.get("SystemDrive", "C:") + "\\"
        
        # Phase 1: Scan C:\ top level
        all_folders = []
        
        folders_to_scan = [
            os.path.join(system_drive, "Users"),
            os.path.join(system_drive, "Windows"),
            os.path.join(system_drive, "Program Files"),
            os.path.join(system_drive, "Program Files (x86)"),
            os.path.join(system_drive, "ProgramData"),
            os.path.join(system_drive, "Windows.old"),
        ]
        
        for folder in folders_to_scan:
            if not self.scanning:
                break
            
            if not os.path.exists(folder):
                continue
            
            if progress_callback:
                progress_callback(-1, -1, f"统计 {os.path.basename(folder)} ...")
            
            # Get first-level children sizes
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        if not self.scanning:
                            break
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                size, _, approx = get_dir_size_fast(entry.path, timeout=3.0)
                                if size > 1024 * 1024:  # > 1MB only
                                    all_folders.append({
                                        "name": entry.name,
                                        "parent": os.path.basename(folder),
                                        "path": entry.path,
                                        "size": size,
                                        "approx": approx,
                                    })
                            elif entry.is_file(follow_symlinks=False):
                                size = entry.stat().st_size
                                if size > 50 * 1024 * 1024:  # > 50MB files
                                    all_folders.append({
                                        "name": entry.name,
                                        "parent": os.path.basename(folder),
                                        "path": entry.path,
                                        "size": size,
                                        "approx": False,
                                    })
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass
        
        # Sort by size descending, take top 10
        all_folders.sort(key=lambda x: x["size"], reverse=True)
        self.top_folders = all_folders[:10]
    
    def run(self, progress_callback=None, complete_callback=None):
        """Run full scan in background thread."""
        self.scanning = True
        
        try:
            if progress_callback:
                progress_callback(0, 0, "正在扫描垃圾文件...")
            self.scan_targets(progress_callback)
            
            if progress_callback:
                progress_callback(0, 0, "正在统计 C 盘大文件夹...")
            self.scan_top_folders(progress_callback)
        finally:
            self.scanning = False
        
        if complete_callback:
            complete_callback()
    
    def stop(self):
        """Stop scanning."""
        self.scanning = False


# ============================================================
# GUI Application
# ============================================================

class PcCleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("720x640")
        self.root.minsize(600, 500)
        
        # State
        self.results = []
        self.top_folders = []
        self.check_vars = {}  # item_name -> tk.BooleanVar
        self.scan_engine = ScanEngine()
        self.advanced_visible = False
        self.is_admin = is_admin()
        self.cleaning = False  # Prevent double-clean
        
        # Setup UI
        self.setup_ui()
        
        # Set window icon (optional, try)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass
    
    def setup_ui(self):
        """Build the GUI."""
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ---- Header ----
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        title_label = ttk.Label(header_frame, text=APP_TITLE, 
            font=("Microsoft YaHei UI", 16, "bold"))
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = ttk.Label(header_frame, 
            text="安全扫描系统盘垃圾，回收宝贵空间",
            font=("Microsoft YaHei UI", 9),
            foreground="gray")
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # ---- Admin Warning Banner ----
        self.admin_warning = tk.Frame(main_frame, bg=COLOR_WARNING_BG)
        self.admin_warning.pack(fill=tk.X, pady=(0, 5))
        
        admin_icon = tk.Label(self.admin_warning, text="⚠", 
            bg=COLOR_WARNING_BG, fg=COLOR_WARNING_FG,
            font=("Microsoft YaHei UI", 14))
        admin_icon.pack(side=tk.LEFT, padx=(5, 5), pady=2)
        
        admin_text = tk.Label(self.admin_warning, 
            text="建议右键点击程序图标 → 以管理员身份运行，可清理更多系统垃圾",
            bg=COLOR_WARNING_BG, fg=COLOR_WARNING_FG,
            font=("Microsoft YaHei UI", 9))
        admin_text.pack(side=tk.LEFT, pady=4)
        
        if self.is_admin:
            self.admin_warning.pack_forget()
        
        # ---- Top button bar ----
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 10))
        
        self.scan_btn = ttk.Button(btn_frame, text=" 开始扫描 C 盘 ", 
            command=self.start_scan, style="Accent.TButton")
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.status_label = ttk.Label(btn_frame, text="就绪，点击扫描开始", 
            font=("Microsoft YaHei UI", 9), foreground="gray")
        self.status_label.pack(side=tk.LEFT)
        
        # ---- Progress bar ----
        self.progress = ttk.Progressbar(main_frame, mode="determinate")
        
        # ---- Results Area (Notebook with tabs) ----
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Tab 1: Safe cleanup items
        self.safe_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.safe_frame, text=" 安全清理 ")
        
        # Safe items - treeview with checkbox
        self.safe_tree = self._create_treeview(self.safe_frame)
        
        # Tab 2: Top folders
        self.folder_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.folder_frame, text=" C盘大文件夹 TOP10 ")
        
        self.folder_tree = self._create_folder_treeview(self.folder_frame)
        
        # ---- Advanced section (collapsed by default) ----
        self.advanced_container = ttk.Frame(main_frame)
        self.advanced_container.pack(fill=tk.X, pady=(0, 0))
        
        self.adv_toggle_btn = ttk.Button(self.advanced_container, 
            text="▸ 高级选项（展开）", command=self.toggle_advanced,
            style="Link.TButton")
        self.adv_toggle_btn.pack(anchor=tk.W)
        
        self.advanced_frame = ttk.Frame(main_frame)
        # hidden by default
        
        self.cautious_label = ttk.Label(self.advanced_frame, 
            text="谨慎处理 - 请确认后再清理",
            font=("Microsoft YaHei UI", 10, "bold"),
            foreground=COLOR_CAUTIOUS)
        self.cautious_label.pack(anchor=tk.W, pady=(5, 2))
        
        self.cautious_tree = self._create_treeview(self.advanced_frame)
        self.cautious_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        cautious_scroll = ttk.Scrollbar(self.advanced_frame, orient=tk.VERTICAL,
            command=self.cautious_tree.yview)
        cautious_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.cautious_tree.configure(yscrollcommand=cautious_scroll.set)
        
        # ---- Bottom bar ----
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(10, 5))
        
        self.summary_label = ttk.Label(bottom_frame, 
            text="", font=("Microsoft YaHei UI", 10))
        self.summary_label.pack(side=tk.LEFT)
        
        self.clean_btn = ttk.Button(bottom_frame, text="清理选中项", 
            command=self.start_clean, state=tk.DISABLED)
        self.clean_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.exit_btn = ttk.Button(bottom_frame, text="退出", 
            command=self.root.destroy)
        self.exit_btn.pack(side=tk.RIGHT)
        
        # Configure styles
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Link.TButton", font=("Microsoft YaHei UI", 9))
        
        self.notebook.pack_forget()  # Hide until scan complete
    
    def _create_treeview(self, parent):
        """Create a Treeview for scan results with checkbox column."""
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)
        
        columns = ("checked", "name", "size", "desc")
        tree = ttk.Treeview(container, columns=columns, show="headings",
            selectmode="none")
        
        tree.heading("checked", text="选择")
        tree.heading("name", text="项目")
        tree.heading("size", text="大小")
        tree.heading("desc", text="说明")
        
        tree.column("checked", width=45, anchor=tk.CENTER, stretch=False)
        tree.column("name", width=150, stretch=True)
        tree.column("size", width=80, anchor=tk.E, stretch=False)
        tree.column("desc", width=200, stretch=True)
        
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Click handler for checkbox toggle
        tree.bind("<Button-1>", lambda e: self._on_tree_click(e, tree))
        
        return tree
    
    def _create_folder_treeview(self, parent):
        """Create a Treeview for top folders."""
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)
        
        columns = ("rank", "path", "size", "note")
        tree = ttk.Treeview(container, columns=columns, show="headings",
            selectmode="none")
        
        tree.heading("rank", text="#")
        tree.heading("path", text="文件夹路径")
        tree.heading("size", text="大小")
        tree.heading("note", text="备注")
        
        tree.column("rank", width=35, anchor=tk.CENTER, stretch=False)
        tree.column("path", width=350, stretch=True)
        tree.column("size", width=90, anchor=tk.E, stretch=False)
        tree.column("note", width=100, stretch=True)
        
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        return tree
    
    def _on_tree_click(self, event, tree):
        """Handle checkbox click in treeview."""
        region = tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        
        column = tree.identify_column(event.x)
        if column != "#1":  # Only react to first column (checkbox)
            return
        
        item = tree.identify_row(event.y)
        if not item:
            return
        
        name = tree.item(item, "values")[1]
        if name in self.check_vars:
            new_val = not self.check_vars[name].get()
            self.check_vars[name].set(new_val)
            self._update_checkbox_display(tree, item, new_val)
            self._update_summary()
    
    def _update_checkbox_display(self, tree, item, checked):
        """Update the checkbox symbol in the treeview."""
        values = list(tree.item(item, "values"))
        values[0] = "☑" if checked else "☐"
        tree.item(item, values=values)
    
    def _populate_tree(self, tree, items, tag):
        """Fill a treeview with scan results."""
        tree.delete(*tree.get_children())
        for item in items:
            name = item["name"]
            self.check_vars[name] = tk.BooleanVar(value=item["checked"])
            
            display_item = tree.insert("", tk.END, values=(
                "☑" if item["checked"] else "☐",
                name,
                format_size(item["size"]),
                item["desc"]
            ), tags=(tag,))
            item["_tree_id"] = display_item
        
        # Apply tag colors
        if tag == "safe":
            tree.tag_configure("safe", background=COLOR_BG_SAFE)
        elif tag == "cautious":
            tree.tag_configure("cautious", background=COLOR_BG_CAUTIOUS)
    
    def _populate_folder_tree(self, tree, folders):
        """Fill the folder treeview with top 10 results."""
        tree.delete(*tree.get_children())
        for i, folder in enumerate(folders):
            approx = "(约)" if folder.get("approx") else ""
            rank = i + 1
            tree.insert("", tk.END, values=(
                f"#{rank}",
                folder["path"],
                format_size(folder["size"]),
                approx
            ))
        
        tree.tag_configure("info", background=COLOR_BG_INFO)
    
    def toggle_advanced(self):
        """Toggle the advanced/cautious section visibility."""
        self.advanced_visible = not self.advanced_visible
        if self.advanced_visible:
            self.advanced_frame.pack(fill=tk.X, pady=(5, 0))
            self.adv_toggle_btn.configure(text="▾ 高级选项（收起）")
        else:
            self.advanced_frame.pack_forget()
            self.adv_toggle_btn.configure(text="▸ 高级选项（展开）")
    
    def _update_summary(self):
        """Update the summary label with total space to be freed."""
        total = 0
        for name, var in self.check_vars.items():
            if var.get():
                for r in self.results:
                    if r["name"] == name:
                        total += r["size"]
                        break
        
        self.summary_label.config(
            text=f"预计释放空间: {format_size(total)}",
            foreground=COLOR_SAFE if total > 0 else "gray"
        )
        self.clean_btn.config(state=tk.NORMAL if total > 0 else tk.DISABLED)
    
    def _scan_complete(self):
        """Called when scan finishes."""
        def _update():
            self.progress.stop()
            self.progress.pack_forget()
            self.scan_btn.config(state=tk.NORMAL, text="重新扫描")
            self.status_label.config(text=f"扫描完成，共发现 {len(self.results)} 个可清理项",
                foreground="green")
            
            # Show results
            self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
            
            # Populate safe items
            safe_items = [r for r in self.results if r["level"] == "safe"]
            self._populate_tree(self.safe_tree, safe_items, "safe")
            
            # Populate cautious items
            cautious_items = [r for r in self.results if r["level"] == "cautious"]
            self._populate_tree(self.cautious_tree, cautious_items, "cautious")
            
            # Populate top folders
            self._populate_folder_tree(self.folder_tree, self.top_folders)
            
            self._update_summary()
            
            # If no safe items found, still enable clean for cautious
            if not safe_items:
                self.notebook.select(self.folder_frame)
        
        self.root.after(0, _update)
    
    def start_scan(self):
        """Start the scanning process."""
        self.scan_btn.config(state=tk.DISABLED, text="正在扫描...")
        self.status_label.config(text="正在扫描...")
        self.notebook.pack_forget()
        self.advanced_frame.pack_forget()
        self.advanced_visible = False
        self.adv_toggle_btn.configure(text="▸ 高级选项（展开）")
        
        # Reset
        self.results = []
        self.check_vars = {}
        self.safe_tree.delete(*self.safe_tree.get_children())
        self.cautious_tree.delete(*self.cautious_tree.get_children())
        self.folder_tree.delete(*self.folder_tree.get_children())
        self.summary_label.config(text="")
        self.clean_btn.config(state=tk.DISABLED)
        
        # Show progress bar (indeterminate mode - bouncing)
        self.progress.pack(fill=tk.X, pady=(5, 0))
        self.progress.config(mode="indeterminate")
        self.progress.start(10)
        
        def do_scan():
            engine = ScanEngine()
            engine.scanning = True
            # Phase 1: Scan predefined targets
            engine.scan_targets(
                lambda c, t, m: self.root.after(0, 
                    lambda _c=c, _t=t, _m=m: self.status_label.config(text=f"正在扫描 ({_c}/{_t}): {_m}"))
            )
            # Phase 2: Scan top folders
            engine.scan_top_folders(
                lambda c, t, m: self.root.after(0,
                    lambda _m=m: self.status_label.config(text=_m))
            )
            self.results = engine.results
            self.top_folders = engine.top_folders
            self._scan_complete()
        
        thread = threading.Thread(target=do_scan, daemon=True)
        thread.start()
    
    def start_clean(self):
        """Start the cleanup process."""
        if self.cleaning:
            return
        
        items_to_delete = []
        total_size = 0
        
        for name, var in self.check_vars.items():
            if var.get():
                for r in self.results:
                    if r["name"] == name:
                        items_to_delete.append(r)
                        total_size += r["size"]
                        break
        
        if not items_to_delete:
            messagebox.showinfo("提示", "没有选中任何清理项。")
            return
        
        # Show confirmation
        item_list = "\n".join(
            f"  * {r['name']}  ({format_size(r['size'])})" 
            for r in items_to_delete
        )
        
        confirm = messagebox.askyesno(
            "确认清理",
            f"即将清理以下项目：\n\n{item_list}\n\n"
            f"预计释放 {format_size(total_size)} 空间\n\n"
            f"清理的文件将移至回收站（可还原）。\n无法删除的文件将标记为开机后清理。\n确定继续吗？",
            icon="warning"
        )
        
        if not confirm:
            return
        
        # Do cleanup in background
        self.cleaning = True
        self.clean_btn.config(state=tk.DISABLED, text="清理中...")
        self.status_label.config(text="正在清理...")
        
        # Write log
        log_file = os.path.join(os.path.expanduser("~"), f"PC清理助手_日志_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        log_entries = []
        
        def do_clean():
            success_count = 0
            reboot_count = 0
            fail_count = 0
            freed_bytes = 0
            
            for item in items_to_delete:
                path = item["path"]
                item_name = item["name"]
                
                # Special handling for Windows.old
                if "Windows.old" in path:
                    self.root.after(0, lambda: self.status_label.config(
                        text="正在打开系统磁盘清理工具..."
                    ))
                    _success = open_disk_cleanup()
                    if _success:
                        success_count += 1
                        freed_bytes += item["size"]
                        log_entries.append("[OK] Windows.old - 已打开磁盘清理工具，请手动勾选\"以前版本的Windows\"进行清理")
                    else:
                        fail_count += 1
                        log_entries.append("[FAIL] Windows.old - 无法打开磁盘清理工具")
                    continue
                
                # Special handling for Windows Update download
                # Files here are locked by wuauserv / BITS services
                if "SoftwareDistribution" in path and "Download" in path:
                    services_stopped = False
                    if self.is_admin:
                        self.root.after(0, lambda: self.status_label.config(
                            text="正在暂停 Windows Update 服务..."
                        ))
                        subprocess.run(["net", "stop", "wuauserv", "/y"],
                            capture_output=True, timeout=30)
                        subprocess.run(["net", "stop", "bits", "/y"],
                            capture_output=True, timeout=30)
                        services_stopped = True
                        log_entries.append("[服务] Windows Update / BITS 已暂停")
                    
                    try:
                        self.root.after(0, lambda _n=item_name: self.status_label.config(
                            text=f"正在清理: {_n}..."
                        ))
                        d, r, f, b, errs = clean_directory_contents(path)
                        success_count += d
                        reboot_count += r
                        fail_count += f
                        freed_bytes += b
                        if d + r > 0 or f > 0:
                            log_entries.append(f"[Windows更新清理] 已移至回收站{d}, 重启删{r}, 跳过{f}")
                        if errs:
                            log_entries.extend(errs[:20])
                    finally:
                        if services_stopped:
                            self.root.after(0, lambda: self.status_label.config(
                                text="正在恢复 Windows Update 服务..."
                            ))
                            subprocess.run(["net", "start", "wuauserv"],
                                capture_output=True, timeout=30)
                            subprocess.run(["net", "start", "bits"],
                                capture_output=True, timeout=30)
                            log_entries.append("[服务] Windows Update / BITS 已恢复")
                    continue
                
                # For Firefox, handle multi-profile
                if path and os.path.isdir(path) and "Firefox" in path:
                    try:
                        for profile in os.scandir(path):
                            cache_dir = os.path.join(profile.path, "cache2")
                            if os.path.exists(cache_dir):
                                d, r, f, b, errs = clean_directory_contents(cache_dir)
                                success_count += d
                                reboot_count += r
                                fail_count += f
                                freed_bytes += b
                                log_entries.append(f"[目录清理] {cache_dir}: 移至回收站{d}, 重启删{r}, 跳过{f}")
                                log_entries.extend(errs[:20])
                    except (PermissionError, OSError):
                        fail_count += 1
                        log_entries.append(f"[FAIL] {path} - 权限不足")
                    continue
                
                if not os.path.exists(path):
                    log_entries.append(f"[SKIP] {path} - 文件不存在")
                    continue
                
                # Directories: clean contents
                if os.path.isdir(path):
                    self.root.after(0, lambda _n=item_name: self.status_label.config(
                        text=f"正在清理: {_n}..."
                    ))
                    d, r, f, b, errs = clean_directory_contents(path)
                    success_count += d
                    reboot_count += r
                    fail_count += f
                    freed_bytes += b
                    if d + r > 0 or f > 0:
                        log_entries.append(f"[目录清理] {path}: 移至回收站{d}, 重启删{r}, 跳过{f}")
                    if errs:
                        log_entries.extend(errs[:20])
                else:
                    # Single file
                    result, reason = delete_file(path)
                    if result == "recycled" or result == "deleted":
                        success_count += 1
                        freed_bytes += item["size"]
                        log_entries.append(f"[回收站] {path}")
                    elif result == "reboot":
                        reboot_count += 1
                        freed_bytes += item["size"]
                        log_entries.append(f"[重启删] {path}")
                    else:
                        fail_count += 1
                        log_entries.append(f"[FAIL] {path} - {reason}")
            
            # Write log
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"PC清理助手 v{VERSION} 清理日志\n")
                f.write(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"管理员权限: {'是' if self.is_admin else '否'}\n")
                f.write(f"清理项数: 回收站 {success_count}, 重启后删除 {reboot_count}, 失败 {fail_count}\n")
                f.write(f"释放空间: {format_size(freed_bytes)}\n")
                f.write("-" * 50 + "\n")
                f.write("\n".join(log_entries))
            
            self.root.after(0, lambda: self._clean_complete(
                success_count, reboot_count, fail_count, freed_bytes, log_file))
        
        thread = threading.Thread(target=do_clean, daemon=True)
        thread.start()
    
    def _clean_complete(self, success, reboot, fail, freed, log_file):
        """Called when cleanup finishes."""
        self.cleaning = False
        self.clean_btn.config(state=tk.NORMAL, text="清理选中项")
        self.status_label.config(
            text=f"清理完成，释放 {format_size(freed)} 空间",
            foreground=COLOR_SAFE
        )
        
        msg = f"清理完成！\n\n"
        msg += f"已删除: {success} 项\n"
        if reboot:
            msg += f"重启后删除: {reboot} 项\n"
        if fail:
            msg += f"跳过: {fail} 项\n"
        msg += f"\n释放空间: {format_size(freed)}\n"
        if reboot:
            msg += f"\n有 {reboot} 个文件将在下次重启后自动清理。"
        msg += f"\n\n详细日志已保存到:\n{log_file}"
        
        messagebox.showinfo("清理完成", msg)


# ============================================================
# Main Entry
# ============================================================

def main():
    root = tk.Tk()
    
    # Set DPI awareness for crisp fonts on HiDPI
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    
    app = PcCleanerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
