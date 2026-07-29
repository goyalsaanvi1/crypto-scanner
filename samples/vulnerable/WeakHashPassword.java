import java.security.MessageDigest;

public class WeakHashPassword {
    public static boolean checkPassword(String password, String storedHash) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digestBytes = md.digest(password.getBytes());
        String passwordHash = bytesToHex(digestBytes);
        return passwordHash.equals(storedHash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
