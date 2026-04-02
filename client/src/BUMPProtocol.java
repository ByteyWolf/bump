import javax.microedition.io.*;
import java.io.*;

public class BUMPProtocol {
    public static final int STATE_DISCONNECTED = 0;
    public static final int STATE_CONNECTING = 1;
    public static final int STATE_CONNECTED = 2;

    public StreamConnection conn = null;
    public volatile byte currentState = STATE_DISCONNECTED;
    public Exception lastException = null;

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

    private class Reader implements Runnable {
        public void run() {
            try {
                // todo: here we receive
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
}
