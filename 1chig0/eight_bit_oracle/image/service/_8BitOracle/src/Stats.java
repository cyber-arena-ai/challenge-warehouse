import java.io.Serializable;

public class Stats {

    private int connectionCount;
    private int questionAnswered;
    private static Stats s = null;

    private Stats() {
        this.connectionCount = 0;
        this.questionAnswered = 0;
    }

    public static Stats getInstance() {
        if (s == null) {
            s = new Stats();
        }
        return s;
    }

    public void incQuestionCount() {
        questionAnswered = questionAnswered + 1;
    }

    public void incConnectionCount() {
        connectionCount = connectionCount + 1;
    }

    public void decConnectionCount() {
        connectionCount = connectionCount - 1;
    }

    public int getConnectionCount() {
        return connectionCount;
    }

    public int getQuestionAnswered() {
        return questionAnswered;
    }
}
