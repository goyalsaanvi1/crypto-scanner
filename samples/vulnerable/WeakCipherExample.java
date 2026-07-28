import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class WeakCipherExample {
    public static void main(String[] args) throws Exception {
        SecretKeySpec key = new SecretKeySpec("8bytekey".getBytes(), "DES");
        Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");
        des.init(Cipher.ENCRYPT_MODE, key);

        SecretKeySpec tripleDesKey = new SecretKeySpec("24byteslongkeyfortripledes".getBytes(), "DESede");
        Cipher tripleDes = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        tripleDes.init(Cipher.ENCRYPT_MODE, tripleDesKey);

        SecretKeySpec rc4Key = new SecretKeySpec("streamcipherkey".getBytes(), "RC4");
        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.ENCRYPT_MODE, rc4Key);

        SecretKeySpec blowfishKey = new SecretKeySpec("blowfishkey".getBytes(), "Blowfish");
        Cipher blowfish = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        blowfish.init(Cipher.ENCRYPT_MODE, blowfishKey);
    }
}
