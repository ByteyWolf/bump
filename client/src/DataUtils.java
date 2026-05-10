public class DataUtils {
    public static int readInt(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 24) |
            ((b[offset + 1] & 0xFF) << 16) |
            ((b[offset + 2] & 0xFF) << 8)  |
            (b[offset + 3] & 0xFF);
    }
    public static long readLong(byte[] b, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (b[offset + i] & 0xFFL);
        }
        return value;
    }
    public static short readShort(byte[] b, int offset) {
        return (short)(((b[offset] & 0xFF) << 8) |
            (b[offset + 1] & 0xFF));
    }

    public static void writeInt(byte[] b, int offset, int value) {
        b[offset]     = (byte) (value >> 24);
        b[offset + 1] = (byte) (value >> 16);
        b[offset + 2] = (byte) (value >> 8);
        b[offset + 3] = (byte) (value);
    }

    public static void writeLong(byte[] b, int offset, long value) {
        b[offset]     = (byte) (value >> 56);
        b[offset + 1] = (byte) (value >> 48);
        b[offset + 2] = (byte) (value >> 40);
        b[offset + 3] = (byte) (value >> 32);
        b[offset + 4] = (byte) (value >> 24);
        b[offset + 5] = (byte) (value >> 16);
        b[offset + 6] = (byte) (value >> 8);
        b[offset + 7] = (byte) (value);
    }

    public static void writeShort(byte[] b, int offset, short value) {
        b[offset]     = (byte) (value >> 8);
        b[offset + 1] = (byte) (value);
    }
}
