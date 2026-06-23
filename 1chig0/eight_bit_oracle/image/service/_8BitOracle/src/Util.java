import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;
import java.security.MessageDigest;
import java.util.Date;
import java.text.SimpleDateFormat;
public class Util {

    Random rnd;
    Message msg;
    Stats stats;


    public Util() {
        this.rnd = new Random();
        this.msg = Message.getInstance();
        this.stats = Stats.getInstance();
    }

    public String createChallenge(){
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] digest = md5.digest(transform(rnd.nextInt()).toString().getBytes());
            StringBuilder builder = new StringBuilder();
            for (byte b : digest) {
                builder.append(String.format("%02x", Byte.toUnsignedInt(b)));
            }

            String challenge = builder.toString();
            Util.debug("Created challenge: " + challenge);
            return challenge;
        }
        catch (NoSuchAlgorithmException e) {
            Util.debug("Could not create challenge");
        }
        return null;
    }




    public String randomMessage() {
        ArrayList<String> answers = Message.getInstance().getMessages();
        return answers.get(this.rnd.nextInt(answers.size()));
    }


    public String getStats() {
        return getUUID() + " " + stats.getQuestionAnswered() + " " + stats.getConnectionCount();
    }

    public BigInteger transform(int number) {
        BigInteger num = BigInteger.valueOf(number);
        if (num.compareTo(BigInteger.ZERO) <= 0) {
            return num.multiply(BigInteger.TWO).abs();
        }
        return num.multiply(BigInteger.TWO).add(BigInteger.valueOf(-1)).abs();

    }

    public void incQuestionCount() {
        stats.incQuestionCount();
    }

    public void incConnectionCount() {
        stats.incConnectionCount();
    }

    public void decConnectionCount() {
        stats.decConnectionCount();
    }

    private String getUUID() {
        int number = rnd.nextInt();
        BigInteger num = transform(number);
        return num.toString(16);
    }

    public static void debug(String message) {
        String timeStamp = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date());
        System.out.println("[" + timeStamp + "]: " + message);
    }




}
