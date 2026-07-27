import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StaticIvExample {
    private static final byte[] IV = { 0,1,2,3,4,5,6,7,8,9,10,11 };

    public static void main(String[] args) throws Exception {
        SecretKeySpec key = new SecretKeySpec("some16bytekey!!!".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    }
}
