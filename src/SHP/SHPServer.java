package SHP;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class SHPServer {
    ServerSocket serverSock;
    Socket sock;
    InputStream in;
    OutputStream out;
    int port;

    public SHPServer() { this(3333); }

    public SHPServer(int port) {
        this.port = port;

        try {
            this.serverSock = new ServerSocket(port);
            this.sock = serverSock.accept();
            System.out.println("inet: " + sock.getInetAddress());
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public void handshake() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(out);
            oos.writeObject(new SHPHeader(0x1, 0x2, 0x3));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void destroy() {
        try {
            in.close();
            out.close();
            sock.close();
            serverSock.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
