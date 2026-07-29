import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class WeakPbkdf {
    public static byte[] deriveKey(char[] password) throws Exception {
        byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
        PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
}
