package ua.byteywolf.bump;
import java.util.Hashtable;
import java.util.Enumeration;

/**
 * A J2ME-compatible thread-safe Hashtable replacement 
 * where threads can block and wait for keys to appear.
 */
public class WaitableDict {
    private final Hashtable data = new Hashtable();
    private boolean anyEventSet = false;
    private KeyPair lastWritten = null;

    /**
     * Helper class to mimic Python's tuple return for waitAny().
     */
    public static class KeyPair {
        public Object key;
        public Object value;

        public KeyPair(Object key, Object value) {
            this.key = key;
            this.value = value;
        }
    }

    public WaitableDict() {
    }

    /**
     * Constructor to initialize with existing data.
     */
    public WaitableDict(Hashtable initialData) {
        if (initialData != null) {
            Enumeration keys = initialData.keys();
            while (keys.hasMoreElements()) {
                Object key = keys.nextElement();
                Object val = initialData.get(key);
                this.put(key, val);
            }
        }
    }

    private synchronized void notifyWrite(Object key, Object value) {
        lastWritten = new KeyPair(key, value);
        anyEventSet = true;
        // Wake up all threads waiting on either waitKey() or waitAny()
        this.notifyAll();
    }

    // ── Hashtable Interface Parity ───────────────────────────────────────────

    public synchronized void put(Object key, Object value) {
        data.put(key, value);
        notifyWrite(key, value);
    }

    public synchronized Object get(Object key) {
        return data.get(key);
    }

    public synchronized Object remove(Object key) {
        return data.remove(key);
    }

    public synchronized boolean containsKey(Object key) {
        return data.containsKey(key);
    }

    public synchronized int size() {
        return data.size();
    }

    public synchronized void clear() {
        data.clear();
        anyEventSet = false;
        lastWritten = null;
    }

    // ── Waitable Extras ───────────────────────────────────────────────────────

    /**
     * Block until `key` exists, then return its value. 
     * 
     * @param timeoutMs Timeout in milliseconds. Use 0 to wait indefinitely.
     * @return The value associated with the key, or null if timed out.
     */
    public synchronized Object waitKey(Object key, long timeoutMs) {
        long startTime = System.currentTimeMillis();
        long remaining = timeoutMs;

        while (!data.containsKey(key)) {
            if (timeoutMs > 0 && remaining <= 0) {
                break;
            }
            try {
                if (timeoutMs == 0) {
                    this.wait();
                } else {
                    this.wait(remaining);
                    remaining = timeoutMs - (System.currentTimeMillis() - startTime);
                }
            } catch (InterruptedException e) {
                return null;
            }
        }
        return data.get(key);
    }

    /**
     * Block until any key is written, then return a KeyPair(key, value).
     * 
     * @param timeoutMs Timeout in milliseconds. Use 0 to wait indefinitely.
     * @return KeyPair container holding the key and value, or null if timed out.
     */
    public synchronized KeyPair waitAny(long timeoutMs) {
        long startTime = System.currentTimeMillis();
        long remaining = timeoutMs;

        while (!anyEventSet) {
            if (timeoutMs > 0 && remaining <= 0) {
                break;
            }
            try {
                if (timeoutMs == 0) {
                    this.wait();
                } else {
                    this.wait(remaining);
                    remaining = timeoutMs - (System.currentTimeMillis() - startTime);
                }
            } catch (InterruptedException e) {
                return null;
            }
        }

        if (anyEventSet) {
            anyEventSet = false;
            return lastWritten;
        }
        return null;
    }
}