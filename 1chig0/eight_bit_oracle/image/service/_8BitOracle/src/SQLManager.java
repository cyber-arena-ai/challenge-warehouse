import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

public class SQLManager {

    private static SQLManager manager = null;
    private Connection conn;
    private SQLManager() {


        try  {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Class.forName("org.newsclub.net.mysql.AFUNIXDatabaseSocketFactoryCJ");

            Properties props = new Properties();
            props.setProperty("socketFactory", "org.newsclub.net.mysql.AFUNIXDatabaseSocketFactoryCJ");
            props.setProperty("junixsocket.file", "/run/mysqld/mysqld.sock");
            props.setProperty("user", "8BitOracle");
            props.setProperty("sslMode", "DISABLED");

            // String url = "jdbc:mysql:///bitoracle?user=bitoracle&socketFactory=org.newsclub.net.mysql.AFUNIXDatabaseSocketFactory&junixsocket.file=/run/mysqld/mysqld.sock";
            // Connection conn = DriverManager.getConnection(url);
            Connection conn = DriverManager.getConnection("jdbc:mysql:///bitoracle", props);
            if (conn != null) {
                Util.debug("Connected to database");
            }
            this.conn = conn;
            createTables();

        } catch (SQLException | ClassNotFoundException e) {
            Util.debug("Could not connect to database");
            Util.debug(e.toString());
            System.exit(1);

        }

    }


    public static SQLManager getInstance() {
        if(manager == null) {
            manager = new SQLManager();
        }
        return manager;
    }

    public Connection getConn() {
        return conn;
    }

    private void createTables(){
        String create_review_table = "CREATE TABLE IF NOT EXISTS reviews (id integer PRIMARY KEY AUTO_INCREMENT, review_text text NOT NULL, public_key text NOT NULL);";
        String create_state_table = "CREATE TABLE IF NOT EXISTS states (id integer PRIMARY KEY AUTO_INCREMENT, state text NOT NULL);";
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(create_review_table);
            stmt.executeUpdate(create_state_table);
        } catch (SQLException e) {
            Util.debug(String.valueOf(e));
            Util.debug("Could not create tables");
            System.exit(1);
        }
    }



}
