import threading
from typing import Any, Iterator


class WaitableDict:
    """
    A drop-in dict replacement where you can wait for a key to appear.

    Regular dict usage works exactly as expected:
        d = WaitableDict()
        d["foo"] = 42
        d["foo"]        # 42
        "foo" in d      # True
        del d["foo"]
        len(d)          # 0

    Blocking wait:
        val = d.wait("foo")             # blocks until "foo" is set
        val = d.wait("foo", timeout=5)  # returns None after 5s if still missing

    Callback on arrival:
        d.on("foo", lambda v: print("got:", v))
        d["foo"] = 99   # prints "got: 99" immediately

    Async (asyncio):
        val = await d.async_wait("foo")
        val = await d.async_wait("foo", timeout=5)
    """

    def __init__(self, *args, **kwargs):
        self._data: dict = dict(*args, **kwargs)
        self._events: dict[Any, threading.Event] = {}
        self._listeners: dict[Any, list] = {}
        self._lock = threading.Lock()

        # Fire callbacks/events for anything passed at construction time
        for k, v in self._data.items():
            self._notify(k, v)

    # ── internal ──────────────────────────────────────────────────────────────

    def _get_event(self, key) -> threading.Event:
        """Get or create the Event for a key (must be called under lock)."""
        if key not in self._events:
            self._events[key] = threading.Event()
            if key in self._data:           # already present → pre-set
                self._events[key].set()
        return self._events[key]

    def _notify(self, key, value):
        """Set the event and fire callbacks for a key."""
        with self._lock:
            ev = self._get_event(key)
            ev.set()
            cbs = list(self._listeners.get(key, []))
        for cb in cbs:
            cb(value)

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
            ev.clear()              # reset so future wait_get blocks again

    def __contains__(self, key):
        return key in self._data

    def __len__(self):
        return len(self._data)

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def __repr__(self):
        return f"WaitableDict({self._data!r})"

    # standard dict helpers
    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def pop(self, key, *args):
        val = self._data.pop(key, *args)
        with self._lock:
            ev = self._events.pop(key, None)
        if ev:
            ev.clear()
        return val

    def update(self, *args, **kwargs):
        tmp = dict(*args, **kwargs)
        for k, v in tmp.items():
            self[k] = v             # goes through __setitem__ → notifies

    def setdefault(self, key, default=None):
        if key not in self._data:
            self[key] = default
        return self._data[key]

    def clear(self):
        keys = list(self._data.keys())
        self._data.clear()
        with self._lock:
            for k in keys:
                ev = self._events.pop(k, None)
                if ev:
                    ev.clear()

    def copy(self):
        return WaitableDict(self._data.copy())

    # ── waitable extras ───────────────────────────────────────────────────────

    def wait(self, key, timeout: float | None = None) -> Any:
        """
        Block until `key` exists, then return its value.
        Returns None on timeout (or the value if already present).
        """
        with self._lock:
            ev = self._get_event(key)
        ev.wait(timeout)
        return self._data.get(key)