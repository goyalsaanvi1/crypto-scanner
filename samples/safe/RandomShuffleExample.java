import java.util.Collections;
import java.util.List;
import java.util.Random;

public class RandomShuffleExample {
    public static void shuffleDeck(List<String> cards) {
        Random random = new Random();
        Collections.shuffle(cards, random);
    }

    public static String pickGreeting(List<String> greetings) {
        Random random = new Random();
        int index = random.nextInt(greetings.size());
        return greetings.get(index);
    }
}
