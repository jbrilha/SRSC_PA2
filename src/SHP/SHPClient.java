package SHP;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class SHPClient {
    Socket sock;
    InputStream in;
    OutputStream out;
    String host;
    int port;

    public SHPClient() { this("localhost", 3333); }

    public SHPClient(String host, int port) {
        this.host = host;
        this.port = port;

        try {
            this.sock = new Socket(host, port);
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public void handshake(String username, String password, String filename, int port) {
        try {
            byte[] buf = new byte[1024];
            in.read(buf);
            SHPHeader ss = SHPHeader.getFromPacket(buf);

            System.out.println("\nSHPHeader: " + ss + "\n");

            var payload = host + "_" + port + "_" + filename;
            out.write(payload.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
		}
    }

    public void destroy() {
        try {
            in.close();
            out.close();
            sock.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
