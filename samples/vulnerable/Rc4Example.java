import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Rc4Example {
    public static void main(String[] args) throws Exception {
        // NOTE: RC4 mentioned here in a comment should not be flagged.
        SecretKeySpec key = new SecretKeySpec("streamcipherkey".getBytes(), "RC4");
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
