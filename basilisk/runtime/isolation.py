"""Restricted worker-process execution for untrusted target scans."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger("basilisk.isolation")


# Restricted workers have a deliberately small process/thread allowance.  Native
# numerical libraries otherwise inherit host defaults and may exhaust that
# allowance before a scan starts (for example, OpenBLAS on GitHub runners).
_NATIVE_THREAD_LIMIT_ENV = (
    "BLIS_NUM_THREADS",
    "GOTO_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "RAYON_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)


class WorkerPolicyViolation(PermissionError):
    """The restricted worker attempted an undeclared local capability."""


@dataclass(frozen=True)
class WorkerAuditPolicy:
    """Python audit-hook policy for scanner filesystem and process access."""

    read_roots: tuple[Path, ...]
    write_roots: tuple[Path, ...]
    read_files: tuple[Path, ...] = ()
    write_prefixes: tuple[Path, ...] = ()
    native_roots: tuple[Path, ...] = ()
    native_library_names: tuple[str, ...] = ()
    allow_subprocess: bool = False

    @staticmethod
    def _resolved(value: Any) -> Path | None:
        if isinstance(value, int):
            return None
        try:
            return Path(os.fspath(value)).expanduser().resolve(strict=False)
        except (TypeError, ValueError, OSError):
            return None

    @staticmethod
    def _within(path: Path, roots: tuple[Path, ...]) -> bool:
        return any(path == root or path.is_relative_to(root) for root in roots)

    def _can_read(self, path: Path) -> bool:
        return path in self.read_files or self._within(
            path, self.read_roots + self.write_roots
        ) or self._matches_write_prefix(path)

    def _matches_write_prefix(self, path: Path) -> bool:
        return any(
            path.parent == prefix.parent and path.name.startswith(prefix.name)
            for prefix in self.write_prefixes
        )

    def _can_write(self, path: Path) -> bool:
        return self._within(path, self.write_roots) or self._matches_write_prefix(path)

    def _allowed_bare_native_library(self, value: Any) -> bool:
        """Allow an explicit system DLL name without enabling DLL search-path loading."""
        try:
            raw = os.fspath(value)
        except TypeError:
            return False
        if not isinstance(raw, str) or not raw or any(marker in raw for marker in ("/", "\\")):
            return False
        name = raw.casefold().removesuffix(".dll")
        if name not in self.native_library_names:
            return False
        return any((root / f"{name}.dll").is_file() for root in self.native_roots)

    @staticmethod
    def _open_is_write(mode: Any, flags: Any) -> bool:
        if isinstance(mode, str) and any(marker in mode for marker in ("w", "a", "x", "+")):
            return True
        numeric_flags = flags if isinstance(flags, int) else (mode if isinstance(mode, int) else 0)
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        return bool(numeric_flags & write_flags)

    def __call__(self, event: str, arguments: tuple[Any, ...]) -> None:
        if event == "open" and arguments:
            path = self._resolved(arguments[0])
            if path is None:
                return
            mode = arguments[1] if len(arguments) > 1 else "r"
            flags = arguments[2] if len(arguments) > 2 else 0
            allowed = self._can_write(path) if self._open_is_write(mode, flags) else self._can_read(path)
            if not allowed:
                raise WorkerPolicyViolation("filesystem access denied by restricted worker policy")
            return

        if event in {"sqlite3.connect"} and arguments:
            path = self._resolved(arguments[0])
            if path is not None and not self._can_write(path):
                raise WorkerPolicyViolation("database access denied by restricted worker policy")
            return

        if event in {"os.mkdir", "os.remove", "os.rmdir", "os.unlink", "os.chmod"} and arguments:
            path = self._resolved(arguments[0])
            if path is not None and not self._can_write(path):
                raise WorkerPolicyViolation("filesystem mutation denied by restricted worker policy")
            return

        if event in {"os.rename", "os.replace"} and len(arguments) >= 2:
            source = self._resolved(arguments[0])
            destination = self._resolved(arguments[1])
            if any(path is not None and not self._can_write(path) for path in (source, destination)):
                raise WorkerPolicyViolation("filesystem rename denied by restricted worker policy")
            return

        if event in {"os.listdir", "os.scandir"} and arguments:
            path = self._resolved(arguments[0])
            if path is not None and not self._can_read(path):
                raise WorkerPolicyViolation("filesystem enumeration denied by restricted worker policy")
            return

        if event == "ctypes.dlopen" and arguments:
            if self._allowed_bare_native_library(arguments[0]):
                return
            path = self._resolved(arguments[0])
            if path is not None and not (
                self._can_read(path) or self._within(path, self.native_roots)
            ):
                raise WorkerPolicyViolation("native library access denied by restricted worker policy")
            return

        if not self.allow_subprocess and (
            event == "subprocess.Popen"
            or event == "os.system"
            or event.startswith("os.spawn")
            or event.startswith("os.exec")
            or event == "os.startfile"
        ):
            raise WorkerPolicyViolation("child process creation denied by restricted worker policy")


def build_worker_audit_policy(
    arguments: dict[str, Any],
    request_path: Path,
) -> WorkerAuditPolicy:
    """Build least-privilege local access rules from non-secret worker arguments."""

    project_root = Path(__file__).resolve().parents[2]
    temporary_root = request_path.resolve().parent
    output_root = Path(arguments.get("output_dir") or "./basilisk-reports").resolve()
    broad_roots = {
        Path(output_root.anchor).resolve(),
        Path.home().resolve(),
        project_root.resolve(),
    }
    if output_root in broad_roots:
        raise ValueError("restricted worker output directory is too broad")

    read_roots = {
        project_root.resolve(),
        temporary_root,
        Path(sys.prefix).resolve(),
        Path(sys.base_prefix).resolve(),
    }
    read_files = {request_path.resolve(), Path(os.devnull).resolve()}
    for name in ("config", "api_key", "auth", "attacker_api_key"):
        value = str(arguments.get(name, "") or "")
        if name == "config" and value:
            read_files.add(Path(value).expanduser().resolve())
        elif value.startswith("@") and len(value) > 1:
            read_files.add(Path(value[1:]).expanduser().resolve())

    session_db = Path("./basilisk-sessions.db").resolve()
    native_roots: tuple[Path, ...] = ()
    native_library_names: tuple[str, ...] = ()
    if os.name == "nt" and os.environ.get("SystemRoot"):
        native_roots = ((Path(os.environ["SystemRoot"]) / "System32").resolve(),)
        # Click and Rich access shell32/kernel32 through ctypes.windll for
        # Windows console handling. Resolve only these exact System32 DLLs,
        # never an arbitrary bare library through the current-directory path.
        native_library_names = ("kernel32", "shell32")
    return WorkerAuditPolicy(
        read_roots=tuple(sorted(read_roots, key=str)),
        write_roots=(temporary_root, output_root),
        read_files=tuple(sorted(read_files, key=str)),
        write_prefixes=(session_db,),
        native_roots=native_roots,
        native_library_names=native_library_names,
        allow_subprocess=False,
    )


def install_worker_audit_policy(
    arguments: dict[str, Any],
    request_path: Path,
) -> WorkerAuditPolicy:
    """Install and retain the worker's irreversible Python audit hook."""

    policy = build_worker_audit_policy(arguments, request_path)
    sys.addaudithook(policy)
    globals()["_WORKER_AUDIT_POLICY"] = policy
    return policy


@dataclass(frozen=True)
class WorkerLimits:
    """Hard process ceilings; request and response ceilings live in RequestExecutor."""

    wall_seconds: int = 7_200
    cpu_seconds: int = 3_600
    memory_bytes: int = 6 * 1024**3
    file_bytes: int = 512 * 1024**2
    open_files: int = 1_024
    child_processes: int = 64

    @classmethod
    def for_mode(cls, mode: str) -> "WorkerLimits":
        profiles = {
            "quick": cls(1_800, 900, 4 * 1024**3, 256 * 1024**2, 512, 32),
            "standard": cls(),
            "deep": cls(21_600, 10_800, 12 * 1024**3, 1024 * 1024**2, 2_048, 96),
            "stealth": cls(21_600, 7_200, 6 * 1024**3, 512 * 1024**2, 1_024, 32),
            "chaos": cls(21_600, 10_800, 16 * 1024**3, 1024 * 1024**2, 4_096, 128),
        }
        return profiles.get(str(mode).casefold(), cls())


def apply_worker_limits(limits: WorkerLimits, *, include_cpu: bool = True) -> str:
    """Apply best available OS limits and return the active backend name."""
    if os.environ.get("BASILISK_DISABLE_PROCESS_ISOLATION", "").casefold() in {
        "1", "true", "yes", "on",
    }:
        return "disabled"
    if os.name == "nt":
        return _apply_windows_job_limits(limits, include_cpu=include_cpu)
    return _apply_posix_limits(limits, include_cpu=include_cpu)


def spawn_restricted_scan(arguments: dict[str, Any]) -> int:
    """Run a scan in a child interpreter without serializing secret values."""
    if os.environ.get("BASILISK_RESTRICTED_WORKER") == "1":
        raise RuntimeError("nested Basilisk scan workers are not allowed")
    for name in ("api_key", "auth", "attacker_api_key"):
        value = str(arguments.get(name, "") or "")
        if value and not value.startswith(("@", "$")):
            raise ValueError(f"worker request contains inline secret field: {name}")

    limits = WorkerLimits.for_mode(str(arguments.get("mode", "standard")))
    with tempfile.TemporaryDirectory(prefix="basilisk-worker-") as temporary:
        request_path = Path(temporary) / "request.json"
        request_path.write_text(
            json.dumps({"arguments": arguments, "limits": asdict(limits)}, sort_keys=True),
            encoding="utf-8",
        )
        try:
            os.chmod(request_path, 0o600)
        except PermissionError:
            pass
        env = os.environ.copy()
        env["BASILISK_RESTRICTED_WORKER"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["TMP"] = temporary
        env["TEMP"] = temporary
        for variable in _NATIVE_THREAD_LIMIT_ENV:
            env[variable] = "1"
        env["TOKENIZERS_PARALLELISM"] = "false"
        command = [sys.executable, "-m", "basilisk.runtime.scan_worker", str(request_path)]
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen(
            command,
            cwd=Path.cwd(),
            env=env,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
        try:
            return int(process.wait(timeout=limits.wall_seconds))
        except subprocess.TimeoutExpired:
            _terminate_worker(process)
            logger.error("Restricted scan worker exceeded %s seconds", limits.wall_seconds)
            return 124
        except KeyboardInterrupt:
            _terminate_worker(process)
            return 130


def _terminate_worker(process: subprocess.Popen[Any]) -> None:
    """Terminate the worker and its process group, then reap it."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
    finally:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _apply_posix_limits(limits: WorkerLimits, *, include_cpu: bool) -> str:
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX runtime
        return "unsupported"

    requested: list[tuple[int, int]] = [
        (resource.RLIMIT_FSIZE, limits.file_bytes),
        (resource.RLIMIT_NOFILE, limits.open_files),
    ]
    if hasattr(resource, "RLIMIT_AS"):
        requested.append((resource.RLIMIT_AS, limits.memory_bytes))
    if include_cpu:
        requested.append((resource.RLIMIT_CPU, limits.cpu_seconds))
    if hasattr(resource, "RLIMIT_NPROC"):
        requested.append((resource.RLIMIT_NPROC, limits.child_processes))

    for resource_id, desired in requested:
        soft, hard = resource.getrlimit(resource_id)
        ceiling = desired if hard == resource.RLIM_INFINITY else min(desired, hard)
        resource.setrlimit(resource_id, (ceiling, hard))
    return "posix_rlimit"


def _apply_windows_job_limits(limits: WorkerLimits, *, include_cpu: bool) -> str:
    """Attach the current process to a Job Object with memory/process/CPU limits."""
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = 0x100 | 0x8 | 0x2000
    info.BasicLimitInformation.ActiveProcessLimit = limits.child_processes
    info.ProcessMemoryLimit = limits.memory_bytes
    if include_cpu:
        info.BasicLimitInformation.LimitFlags |= 0x2
        info.BasicLimitInformation.PerProcessUserTimeLimit = limits.cpu_seconds * 10_000_000
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        error = ctypes.get_last_error()
        if error == 5:  # Already constrained by a parent job, common in CI.
            logger.warning("Current process already belongs to a non-nestable Windows Job Object")
            return "windows_parent_job"
        raise OSError(error, "AssignProcessToJobObject failed")
    # Keep the handle alive for the process lifetime; closing it would terminate the job.
    globals()["_WINDOWS_JOB_HANDLE"] = job
    return "windows_job"
