import java.util.Random;

public class InsecureRandomKey {
    public static byte[] generateKey() {
        Random random = new Random();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        return keyBytes;
    }
}
