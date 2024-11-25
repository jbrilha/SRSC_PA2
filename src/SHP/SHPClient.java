package SHP;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.bouncycastle.util.encoders.Hex;

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
            SHPHeader header = new SHPHeader(0x1, 0x1, 0x1);
            SHPPayload payload = new SHPPayload(username.getBytes());
            SHPPacket packet = new SHPPacket(header, payload);
            System.out.println("sent msg1: " + packet + "\n");
            out.write(packet.toByteArray());

            packet = SHPPacket.fromInputStream(in);
            payload = packet.getPayload();
            header = packet.getHeader();
            String msg2 = Hex.toHexString(payload.getData());
            System.out.println("rec msg2: " + packet + "\n");

            var payl = host + "_" + port + "_" + filename;
            header = new SHPHeader(0x1, 0x1, 0x1);
            payload = new SHPPayload(payl.getBytes());
            packet = new SHPPacket(header, payload);
            out.write(packet.toByteArray());
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
