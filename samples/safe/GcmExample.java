import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class GcmExample {
    public static void main(String[] args) throws Exception {
        // AES/GCM with a properly generated key and random IV - should NOT be flagged
        SecretKey key = KeyProvider.loadKeyFromSecureStore();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    }
}

class KeyProvider {
    static SecretKey loadKeyFromSecureStore() {
        // placeholder: in real code this pulls from a KMS / vault, never hardcoded
        throw new UnsupportedOperationException("not implemented in sample");
    }
}
