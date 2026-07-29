public class ConcatenatedKey {
    private static final String SECRET_KEY = "myS3cr3t" + "Key12345";

    public static void main(String[] args) {
        System.out.println(SECRET_KEY.length());
    }
}
