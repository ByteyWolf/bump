import threading
from typing import Any, Iterator, Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")

class WaitableDict(Generic[K, V]):
    """
    A drop-in dict replacement where you can wait for a key to appear.

    Regular dict usage works exactly as expected:
        d = WaitableDict()
        d["foo"] = 42
        d["foo"]        # 42
        "foo" in d      # True
        del d["foo"]
        len(d)          # 0

    Blocking wait for a specific key:
        val = d.wait("foo")             # blocks until "foo" is set
        val = d.wait("foo", timeout=5)  # returns None after 5s if still missing

    Blocking wait for any key:
        key, val = d.wait_any()             # blocks until anything is set
        key, val = d.wait_any(timeout=5)    # returns None after 5s
    """

    def __init__(self, *args, **kwargs):
        self._data: dict = dict(*args, **kwargs)
        self._events: dict[Any, threading.Event] = {}
        self._lock = threading.Lock()
        self._any_event = threading.Event()
        self._last_written: tuple | None = None

        for k, v in self._data.items():
            self._notify(k, v)

    # ── internal ──────────────────────────────────────────────────────────────

    def _get_event(self, key) -> threading.Event:
        if key not in self._events:
            self._events[key] = threading.Event()
            if key in self._data:
                self._events[key].set()
        return self._events[key]

    def _notify(self, key, value):
        with self._lock:
            ev = self._get_event(key)
            ev.set()
        self._last_written = (key, value)
        self._any_event.set()

    # ── dict interface ────────────────────────────────────────────────────────

    def __setitem__(self, key, value):
        self._data[key] = value
        self._notify(key, value)

    def __getitem__(self, key):
        return self._data[key]

    def __delitem__(self, key):
        with self._lock:
            del self._data[key]
            ev = self._events.pop(key, None)
        if ev:
            ev.clear()

    def __contains__(self, key):
        return key in self._data

    def __len__(self):
        return len(self._data)

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def __repr__(self):
        return f"WaitableDict({self._data!r})"

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):   return self._data.keys()
    def values(self): return self._data.values()
    def items(self):  return self._data.items()

    def pop(self, key, *args):
        val = self._data.pop(key, *args)
        with self._lock:
            ev = self._events.pop(key, None)
        if ev:
            ev.clear()
        return val

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).items():
            self[k] = v

    def setdefault(self, key, default=None):
        if key not in self._data:
            self[key] = default
        return self._data[key]

    def clear(self):
        with self._lock:
            self._data.clear()
            for ev in self._events.values():
                ev.clear()
            self._events.clear()

    def copy(self):
        return WaitableDict(self._data.copy())

    # ── waitable extras ───────────────────────────────────────────────────────

    def wait(self, key, timeout: float | None = None) -> Any:
        """Block until `key` exists, then return its value. Returns None on timeout."""
        with self._lock:
            ev = self._get_event(key)
        ev.wait(timeout)
        return self._data.get(key)

    def wait_any(self, timeout: float | None = None) -> tuple[K, V] | None:
        """Block until any key is written, then return (key, value). Returns None on timeout."""
        self._any_event.wait(timeout)
        self._any_event.clear()
        return self._last_written