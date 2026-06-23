import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private final ServerSocket serverSocket;

    public Server(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    public void start() {
        try {
            Util.debug("Server has started");
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
                Util.debug("A new client has connected");
                Oracle client = new Oracle(socket);

                Thread thread = new Thread(client);
                thread.start();
            }
        } catch (IOException e) {
            closeServer();
        }

    }

    public void closeServer() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
