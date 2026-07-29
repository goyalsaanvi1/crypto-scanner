import javax.crypto.spec.PBEKeySpec;

public class VariableIterationCount {
    public static void main(String[] args) throws Exception {
        int iterations = 1000;
        char[] password = "hunter2".toCharArray();
        byte[] salt = new byte[16];
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
    }
}
