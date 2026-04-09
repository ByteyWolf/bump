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
}
