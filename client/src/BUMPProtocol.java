import javax.microedition.io.*;
import java.io.*;

public class BUMPProtocol {
    public static final int STATE_DISCONNECTED = 0;
    public static final int STATE_CONNECTING = 1;
    public static final int STATE_CONNECTED = 2;

    private StreamConnection conn = null;
    private InputStream instream = null;
    private OutputStream outstream = null;
    public volatile byte currentState = STATE_DISCONNECTED;
    public Exception lastException = null;

    public Queue inQueue = new Queue();
    public Queue outQueue = new Queue();
    public int inCounter = 0;
    public int outCounter = 0; // note: this must be OR'ed with 0xffffffff on send

    private int maxPermissiblePacketSize = 1 * 1024;
    private byte[] secureValue = null;

    public byte connect(String destination) throws IOException {
        if (currentState != STATE_DISCONNECTED) {
            return 0;
        }
        lastException = null;
        currentState = STATE_CONNECTING;
        conn = (StreamConnection) Connector.open(destination);
        new Thread(new Reader()).start();
        new Thread(new Writer()).start();
        return 1;
    }

    public void die() {
        try {
            if (instream != null) instream.close();
            if (outstream != null) outstream.close();
            if (conn != null) conn.close();
        } catch (IOException e) {
        }
        currentState = STATE_DISCONNECTED;
    }

    public byte[] readNBytes(int n) throws IOException {
        byte[] buffer = new byte[n];
        int total = 0;

        while (total < n) {
            int read = instream.read(buffer, total, n - total);
            if (read == -1) {
                throw new IOException("Stream ended early");
            }
            total += read;
        }

        return buffer;
    }

    private class Reader implements Runnable {
        public void run() {
            try {
                synchronized(inQueue) {
                    instream = conn.openInputStream();
                    while (currentState != STATE_DISCONNECTED) {
                        byte[] incount = readNBytes(4);
                        int length = DataUtils.readInt(incount, 0);
                        if (length < 11 || length > maxPermissiblePacketSize) {
                            die();
                            throw new IOException("Invalid or corrupted packet");
                        }
                        
                        // note: its fine to just allocate whatever.
                        // the app will crash with OOM if the server is bad :D
                        // and if your handset doesnt have a literal kilobyte
                        // of free ram then you dont deserve bump
                        byte[] message = readNBytes(length);
                        BUMPBlock block = new BUMPBlock();
                        // TODO: decrypt here
                        block.messageid = DataUtils.readLong(message, 0);
                        block.flags = message[8];
                        block.blocktype = DataUtils.readShort(message, 9);
                        block.raw = message;
                        block.payload_index = 11;
                        inQueue.enqueue(block);
                        inQueue.notifyAll();
                    }
                }
            } catch (IOException e) {
                currentState = STATE_DISCONNECTED;
                lastException = e;
            }
        }
    }

    private class Writer implements Runnable {
        public void run() {
            // todo: here we send
        }
    }

    public class BUMPBlock {
        public long messageid;
        public byte flags;
        public short blocktype;
        public byte[] raw;
        public int payload_index; // index of the first byte of the payload (equals length of header)
    }
}
