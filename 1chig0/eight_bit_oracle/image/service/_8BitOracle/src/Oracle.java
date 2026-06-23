import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.*;
import java.sql.*;
import java.util.Base64;


public class Oracle implements Runnable {



    private Socket socket;
    private BufferedReader reader;
    private BufferedWriter writer;
    private Util util;
    private String challenge;
    private KeyPair keys = null; // temporary


    public Oracle(Socket socket) {
        try {
            this.socket = socket;
            this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.util = new Util();
            this.challenge = util.createChallenge();
            util.incConnectionCount();
        } catch (IOException e) {
            closeConnection(socket, writer, reader);
        }

    }


    @Override
    public void run() {
        String message;
        while (socket.isConnected()) {
            try {
                message = reader.readLine();
                handleMessages(message);
            } catch (IOException | NullPointerException e) {
                closeConnection(socket, writer, reader);
                break;
            }
        }

    }

    private void handleMessages(String message) throws IOException{
        Util.debug("Received Message: " + message);
        if(message.isEmpty()) {
            return;
        }
        if(message.length() >= 2048) {
            sendMessage("ERROR Message to long. Terminating Connection!");
            throw new IOException();
        }
        switch (message.split(" ", 2)[0]) {
            case "MSG":
                handleMessage();
                break;
            case "STATS":
                handleStats();
                break;
            case "REVIEW":
                handleReview(message);
                break;
            case "GETREVIEW":
                handleGetReview(message);
                break;
            case "CHALLENGE":
                handleChallenge(message);
                break;
            case "DECRYPT":
                handleDecryption(message);
                break;
            case "LIST":
                handleList(message);
                break;
            default:
                sendMessage("ERROR METHOD NOT FOUND");
        }
    }

    private void sendMessage(String msg) throws IOException {
        writer.write(msg);
        writer.newLine();
        writer.flush();
    }



    private void closeConnection(Socket socket, BufferedWriter writer, BufferedReader reader) {
        try {
            util.decConnectionCount();
            Util.debug("Client has disconnected");
            if (reader != null) {
                reader.close();
            }
            if (writer != null) {
                writer.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            Util.debug(e.toString());
        }
    }

    private void handleMessage() throws IOException {
        util.incQuestionCount();
        sendMessage("MSG " + util.randomMessage());
    }

    private void handleStats() throws IOException {
        sendMessage("STATS " + util.getStats());
    }

    private void handleReview(String message) throws IOException{
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keys = generator.generateKeyPair();

            String privateKey = new String(Base64.getEncoder().encode(keys.getPrivate().getEncoded()));
            String publicKey = new String(Base64.getEncoder().encode(keys.getPublic().getEncoded()));
            Util.debug("Generated Private Key: " + privateKey);
            Util.debug("Generated Public Key: " + publicKey);
            String review = message.split(" ", 2)[1];


            String query = "INSERT INTO reviews (review_text, public_key) VALUES (?,?)";
            Connection conn = SQLManager.getInstance().getConn();
            PreparedStatement p = conn.prepareStatement(query);
            p.setString(1, review);
            p.setString(2,publicKey);
            p.executeUpdate();


            query = "SELECT id FROM reviews WHERE public_key = ?";
            PreparedStatement p2 = conn.prepareStatement(query);
            p2.setString(1,publicKey);
            ResultSet rs = p2.executeQuery();
            rs.next();
            String id = rs.getString("id");
            Util.debug("Added review to database: " + review + " | " + publicKey);
            sendMessage("REVIEW " + id + ":" + privateKey);
        }
        catch (NoSuchAlgorithmException e) {
            Util.debug("Could not create keypair");
        } catch (SQLException e) {
            Util.debug("Could not add review to SQL database " + e.toString());
        }


    }

    public void handleGetReview(String message) throws IOException {
        String[] id_challenge = message.split(" ", 2)[1].split(":", 2);
        String id = id_challenge[0];
        String query = "SELECT * FROM reviews WHERE id = ?";
        Connection conn = SQLManager.getInstance().getConn();
        try {
            PreparedStatement p = conn.prepareStatement(query);
            p.setString(1, id);
            ResultSet rs = p.executeQuery();
            rs.next();
            String review = rs.getString("review_text");
            String challenge_try = id_challenge[1];
            Util.debug(challenge_try + " " + this.challenge);
            if (challenge_try.equals(this.challenge)) {
                sendMessage("GETREVIEW " + review);
                return;
            }
            this.challenge = util.createChallenge();
            sendMessage("ERROR Mismatch on challenge");
        } catch (SQLException e) {
            Util.debug("Could not retrieve review from SQL database");
        }

    }

    public void handleChallenge(String message) throws IOException {
        Connection conn = SQLManager.getInstance().getConn();
        String query = "SELECT * FROM reviews WHERE id = ?";
        try {
            String id = message.split(" ", 2)[1];
            PreparedStatement p = conn.prepareStatement(query);
            p.setString(1, id);
            ResultSet rs = p.executeQuery();
            rs.next();
            String publicKey = rs.getString("public_key");
            byte[] epkb64 = Base64.getDecoder().decode(publicKey.getBytes());
            EncodedKeySpec epk = new X509EncodedKeySpec(epkb64);
            PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(epk);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, pk);
            byte[] challengeBytes = challenge.getBytes();
            byte[] encryptedChallenge = encryptCipher.doFinal(challengeBytes);
            sendMessage("CHALLENGE " + new String(Base64.getEncoder().encode(encryptedChallenge)));
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException |
               IOException | InvalidKeyException | SQLException | ArrayIndexOutOfBoundsException e) {
            Util.debug("Could not encrypt challenge with public key");
            sendMessage("ERROR Could not retrieve challenge");
        } catch (InvalidKeySpecException e) {
            Util.debug("Some error");
            sendMessage("ERROR Could not retrieve challenge");
        }

    }

    public void handleDecryption(String message) throws IOException {
        try {
            String privateKey = message.split(" ", 2)[1].split(":", 2)[0];
            String encryptedString = message.split(" ", 2)[1].split(":", 2)[1];
            byte[] epkb64 = Base64.getDecoder().decode(privateKey.getBytes());
            EncodedKeySpec epk = new PKCS8EncodedKeySpec(epkb64);
            PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(epk);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedString.getBytes());
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, pk);
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            sendMessage("DECRYPT " + decryptedMessage);

        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
               | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | ArrayIndexOutOfBoundsException  e) {
            String privateKey = message.split(" ", 2)[1].split(":", 2)[0];
            String encryptedString = message.split(" ", 2)[1].split(":", 2)[1];
            sendMessage("ERROR Could not decrypt message");
            Util.debug("Could not decrypt message");
            Util.debug("Using private key: " + privateKey);
            Util.debug("Using encrypted String: " + encryptedString);
            sendMessage("ERROR Could not decrypt challenge");
        }


    }

    public void handleList(String message) throws IOException {
        try {
            Connection conn = SQLManager.getInstance().getConn();
            int  pageNumber = Integer.parseInt(message.split(" ", 2)[1]);
            int per_page = 25;
            int lower = per_page*pageNumber;
            String query = "SELECT id FROM reviews ORDER BY id DESC LIMIT 25 OFFSET ?";
            PreparedStatement p = conn.prepareStatement(query);
            p.setInt(1, lower);
            ResultSet rs = p.executeQuery();
            StringBuilder ret = new StringBuilder("LIST ");

            if (rs.next()) {

                do {
                    ret.append(rs.getString("id")).append(",");
                }
                while (rs.next());
                ret.setLength(ret.length()-1);
                sendMessage(ret.toString());

            }
            else {
                sendMessage("ERROR No reviews found on that page");
            }




        }
        catch (NumberFormatException | SQLException e) {
            sendMessage("ERROR Could not parse page number!");
        }
    }


    private EncodedKeySpec getKey(String raw_key) {
        byte[] epkb64 = Base64.getDecoder().decode(raw_key.getBytes());
        EncodedKeySpec epk = new PKCS8EncodedKeySpec(epkb64);
        return epk;
    }

}
