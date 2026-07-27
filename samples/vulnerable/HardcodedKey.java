import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class HardcodedKey {
    private static final String SECRET_KEY = "myS3cr3tKey12345";

    public static void main(String[] args) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
