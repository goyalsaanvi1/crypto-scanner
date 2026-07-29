import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishExample {
    public static void main(String[] args) throws Exception {
        SecretKeySpec key = new SecretKeySpec("blowfishkey".getBytes(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
