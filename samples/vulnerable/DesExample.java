import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DesExample {
    public static void main(String[] args) throws Exception {
        SecretKeySpec key = new SecretKeySpec("8bytekey".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
