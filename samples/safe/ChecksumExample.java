import java.security.MessageDigest;

public class ChecksumExample {
    public static String computeFileChecksum(byte[] fileBytes) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digestBytes = md.digest(fileBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : digestBytes) {
            sb.append(String.format("%02x", b));
        }
        String fileChecksum = sb.toString();
        return fileChecksum;
    }
}
