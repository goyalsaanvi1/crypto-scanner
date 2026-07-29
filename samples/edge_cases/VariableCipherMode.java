import javax.crypto.Cipher;

public class VariableCipherMode {
    public static void main(String[] args) throws Exception {
        String transformation = "AES/ECB/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(transformation);
    }
}
