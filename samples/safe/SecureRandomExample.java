import java.security.SecureRandom;

public class SecureRandomExample {
    public static byte[] generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        return keyBytes;
    }
}
