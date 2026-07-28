import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

public class InsecureRandomExample {
    public static void main(String[] args) throws Exception {
        Random random = new Random();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
