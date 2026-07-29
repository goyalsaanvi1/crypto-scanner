import java.security.KeyPairGenerator;

public class VariableKeySize {
    public static void main(String[] args) throws Exception {
        int keySize = 1024;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
    }
}
