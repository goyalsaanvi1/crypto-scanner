import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EcbExample {
    public static void main(String[] args) throws Exception {
        byte[] keyBytes = "0123456789abcdef".getBytes();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = cipher.doFinal("some plaintext data".getBytes());
    }
}
