import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Cryptography {
    public static class SHA256 {

        public static byte[] sha256(byte[] input) {
            SHA256Digest digest = new SHA256Digest();
            digest.update(input, 0, input.length);

            byte[] hash = new byte[digest.getDigestSize()]; // 32 bytes for SHA-256
            digest.doFinal(hash, 0);

            return hash;
        }

        public static String toHex(byte[] bytes) {
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {
                String hex = Integer.toHexString(bytes[i] & 0xFF);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            return sb.toString();
        }
    }

    public class AESGCM {

        public static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) throws InvalidCipherTextException {
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv, aad);
            cipher.init(true, params);

            byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
            int len = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
            cipher.doFinal(out, len);

            return out;
        }

        public static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) throws InvalidCipherTextException {
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv, aad);
            cipher.init(false, params);

            byte[] out = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
            cipher.doFinal(out, len);

            return out;
        }
    }

    public class HMACHelper {

        public static byte[] hmacSha256(byte[] key, byte[] data, int offset, int length) {
            HMac hmac = new HMac(new SHA256Digest());
            hmac.init(new KeyParameter(key));

            hmac.update(data, offset, length);

            byte[] out = new byte[hmac.getMacSize()]; // 32 bytes for SHA-256
            hmac.doFinal(out, 0);

            return out;
        }

    }
}
