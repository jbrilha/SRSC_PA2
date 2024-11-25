package SHP;

import java.io.IOException;
import java.io.InputStream;
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
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public String handshake() {
        try {
            SHPHeader header = new SHPHeader(0x1, 0x2, 0x3);
            out.write(header.toByteArray());

            byte[] buf = new byte[1024];
            int read = in.read(buf);
            String bufString = new String(buf, 0, read);
            System.out.println(bufString);
            return bufString;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
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
