package SHP;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
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
            System.out.println("inet: " + sock.getInetAddress());
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public void handshake() {
        try {
            ObjectInputStream ois = new ObjectInputStream(in);
            SHPHeader ss = (SHPHeader) ois.readObject();
            System.out.println("\nSHPHeader: " + ss + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
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
