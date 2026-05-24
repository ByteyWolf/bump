package ua.byteywolf.bump;
import javax.microedition.io.*;

import org.bouncycastle.crypto.digests.SHA256Digest;

import java.io.*;

public class BUMPProtocol {
    public static final int STATE_DISCONNECTED = 0;
    public static final int STATE_CONNECTING = 1;
    public static final int STATE_CONNECTED = 2;

    public static final int HANDSHAKE_STATE_FAILED = -1;
    public static final int HANDSHAKE_STATE_INVALID = 0;
    public static final int HANDSHAKE_STATE_HELLO = 1;
    public static final int HANDSHAKE_STATE_AUTH = 2;

    public static final byte[] PROTOCOL_MAGIC = {'B', 'U', 'M', 'P', 'C', 'l', 'i', 'e', 'n', 't', '1', '.', '1'};

    private StreamConnection conn = null;
    private InputStream instream = null;
    private OutputStream outstream = null;
    public volatile byte currentState = STATE_DISCONNECTED;
    public volatile byte currentHandshakeState = HANDSHAKE_STATE_INVALID;
    public Exception lastException = null;

    public WaitableDict inQueue = new WaitableDict();
    public Queue outQueue = new Queue();
    public long inCounter = 0L;
    public long outCounter = 0xffffffffL;

    private int maxPermissiblePacketSize = 1 * 1024;
    private byte[] secureValue = null;
    private String userName = null;
    private byte[] userPasswordSha256 = null;
    private byte[] encryptionKey = null;

    public long requestCounter = 1L; // UNRELATED TO CRYPTOGRAPHIC COUNTERS, it does not need to be in order!!

    private boolean encryptionEnabled = false;

    public boolean connect(String destination, String username, String password) {
        try {
            if (currentState != STATE_DISCONNECTED) {
                return false;
            }
            SHA256Digest digest = new SHA256Digest();
            byte[] encoded = password.getBytes("UTF-8");
            digest.update(encoded, 0, encoded.length);
            byte[] passwordSha256 = new byte[digest.getDigestSize()];
            digest.doFinal(passwordSha256, 0);

            this.userName = username;
            this.userPasswordSha256 = passwordSha256;
            lastException = null;
            currentState = STATE_CONNECTING;
            conn = (StreamConnection) Connector.open("socket://" + destination);
            new Thread(new Reader()).start();
            new Thread(new Writer()).start();

            handshake();
            return true;
        } catch (Exception e) {
            lastException = e;
            currentState = STATE_DISCONNECTED;
            return false;
        }
    }

    public BUMPBlock buildBlock(long blockId, int blockFlags, short blockType, int payloadLength) {
        byte[] payload = new byte[8 + 1 + 2 + payloadLength];
        DataUtils.writeLong(payload, 0, blockId);
        payload[8] = (byte)(blockFlags & 0xFF);
        DataUtils.writeShort(payload, 9, blockType);

        BUMPBlock block = new BUMPBlock();
        block.blocktype = blockType;
        block.flags = (byte)(blockFlags & 0xFF);
        block.messageid = blockId;
        block.raw = payload;
        block.payload_index = 8 + 1 + 2;
        return block;
    }

    public BUMPBlock buildBlock(int blockFlags, short blockType, int payloadLength) {
        BUMPBlock block = buildBlock(requestCounter, blockFlags, blockType, payloadLength);
        requestCounter++;
        return block;
    }

    public void handshake() {
        // step 1: say hello
        currentHandshakeState = HANDSHAKE_STATE_HELLO;
        byte[] usrRaw = DataUtils.encode(userName);
        int payLen = 13 + usrRaw.length + 1; 
        BUMPBlock block = buildBlock(0, (short)0x0, payLen);
        System.arraycopy(PROTOCOL_MAGIC, 0, block.raw, block.payload_index, PROTOCOL_MAGIC.length);
        System.arraycopy(usrRaw, 0, block.raw, block.payload_index + PROTOCOL_MAGIC.length, usrRaw.length);
        block.raw[block.raw.length - 1] = 0;
        outQueue.enqueue(block);

        WaitableDict.KeyPair response = inQueue.waitAny(10000);
        int blockIdAuth = -1;
        BUMPBlock cryptographicResponse = null;
        if (response != null) {
            blockIdAuth = ((Integer)response.key).intValue();
            cryptographicResponse = (BUMPBlock)(response.value);
        }

        // step 2: prepare for encryption
        currentHandshakeState = HANDSHAKE_STATE_AUTH;
        if (cryptographicResponse == null || cryptographicResponse.blocktype != 0x1) {die(); currentHandshakeState = HANDSHAKE_STATE_FAILED; return;}
        byte[] secVal = new byte[64];
        System.arraycopy(cryptographicResponse.raw, cryptographicResponse.payload_index, secVal, 0, 64); 
        secureValue = secVal;

        // we're good to Establish the Trusted Tunnel :tm: now! let's go!
        encryptionEnabled = true;

        // step 3: prove that we know the password
        payLen = 8;
        block = buildBlock((long)blockIdAuth, 0, (short)0x1, payLen);
        System.arraycopy(DataUtils.encode("BUMPTest"), 0, block.raw, block.payload_index, payLen);
        outQueue.enqueue(block);

        // step 4: wait for the welcome block!
        response = inQueue.waitAny(10000);
        BUMPBlock welcomeBlock = null;
        if (response != null) {
            welcomeBlock = (BUMPBlock)(response.value);
        }

        // at this point the handshake is complete ish
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

    public BUMPBlock request(BUMPBlock block) {
        long idResp = block.messageid;
        outQueue.enqueue(block);
        try {
            while (currentState != STATE_DISCONNECTED) {
                BUMPBlock resp = (BUMPBlock)inQueue.waitKey(new Integer((int)idResp), 5000);
                return resp;
            }
        } catch (Exception e) {}
        
        return null;
    }

    // private stuff

    private byte[] readNBytes(int n) throws IOException {
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

                        if (encryptionEnabled) {
                            if (encryptionKey == null) {
                                encryptionKey = Cryptography.HMACHelper.hmacSha256(userPasswordSha256, secureValue, 16, 48);
                            }
                            
                            byte[] iv = new byte[12];
                            iv[0] = 0; iv[1] = 0; iv[2] = 0; iv[3] = 0;

                            for (int i = 0; i < 8; i++) {
                                iv[11 - i] = (byte) (inCounter >>> (8 * i));
                            }
                            message = Cryptography.AESGCM.decrypt(encryptionKey, iv, message, null);
                        }

                        block.messageid = DataUtils.readLong(message, 0);
                        block.flags = message[8];
                        block.blocktype = DataUtils.readShort(message, 9);
                        block.raw = message;
                        block.payload_index = 11;
                        inQueue.put(new Integer((int) block.messageid), block);
                        inQueue.notifyAll();
                        inCounter++;
                    }
                }
            } catch (Exception e) {
                currentState = STATE_DISCONNECTED;
                lastException = e;
            }
        }
    }

    private class Writer implements Runnable {
        public void run() {
            try {
                synchronized (outQueue) {
                    outstream = conn.openOutputStream();
                    while (currentState != STATE_DISCONNECTED) {
                        BUMPBlock block = (BUMPBlock)(outQueue.dequeue()); // block.raw already includes all necessary headers
                        if (block == null || currentState == STATE_DISCONNECTED) { continue; }
                        if (encryptionEnabled) {
                            if (encryptionKey == null) {
                                encryptionKey = Cryptography.HMACHelper.hmacSha256(userPasswordSha256, secureValue, 16, 48);
                            }
                            
                            byte[] iv = new byte[12];
                            iv[0] = 0; iv[1] = 0; iv[2] = 0; iv[3] = 0;

                            for (int i = 0; i < 8; i++) {
                                iv[11 - i] = (byte) (outCounter >>> (8 * i));
                            }
                            block.raw = Cryptography.AESGCM.encrypt(encryptionKey, iv, block.raw, null);
                        }
                        outCounter++;
                        byte[] payload_len = new byte[4];
                        DataUtils.writeInt(payload_len, 0, block.raw.length);
                        outstream.write(payload_len);
                        outstream.write(block.raw);
                        outstream.flush();
                        block.raw = null;
                        block = null;
                        outQueue.notifyAll();
                    }
                }
            } catch (Exception e) {
                currentState = STATE_DISCONNECTED;
                lastException = e;
            }
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
