package SHP;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;

public class SHPClient {
    CryptoHandler cryptoHandler;
    Socket sock;
    InputStream in;
    OutputStream out;
    String host;
    int port;

    public SHPClient() { this("localhost", 3333); }

    public SHPClient(String host, int port) {
        this.cryptoHandler = new CryptoHandler();
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

    public void sendRequest(String userId, String password, String filename,
                            int port) {
        try {
            var oos = new ObjectOutputStream(out);

            // ---------------- MSG1 ----------------
            SHPPacket packet = prepareMessage1(userId);
            oos.writeObject(packet);

            // ---------------- MSG2 ----------------
            var ois = new ObjectInputStream(in);
            SHPPayload.Type2 payload2 = processMessage2(ois);

            // ---------------- MSG3 ----------------
            packet = prepareMessage3(userId, password, filename, payload2);
            oos.writeObject(packet);

            ois.close();
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SHPPacket prepareMessage1(String userId) throws Exception {
        SHPHeader header = new SHPHeader(0x2, 0x1, 0x1);
        SHPPayload.Type1 payload1 = new SHPPayload.Type1(userId.getBytes());
        SHPPacket packet = new SHPPacket(header, payload1);
        System.out.println("sent msg1: " + packet + "\n");
        return packet;
    }

    private SHPPayload.Type2 processMessage2(ObjectInputStream ois)
        throws Exception {
        SHPPacket packet = (SHPPacket)ois.readObject();
        SHPPayload.Type2 payload2 = (SHPPayload.Type2)packet.getPayload();
        // TODO check header msg type
        // header = packet.getHeader();
        System.out.println("rec msg2: " + packet + "\n");
        return payload2;
    }

    private SHPPacket prepareMessage3(String userId, String password,
                                      String filename,
                                      SHPPayload.Type2 payload2)
        throws Exception {
        byte[] pwHash = cryptoHandler.hashPassword(password);
        SHPEncryptedRequest req =
            new SHPEncryptedRequest(filename, userId, payload2.chall,
                                    CryptoHandler.generateNonces(1), port);
        byte[] pbe = cryptoHandler.encryptRequest(req, pwHash, payload2.salt,
                                                  payload2.counter);

        SHPHeader header = new SHPHeader(0x2, 0x1, 0x3);
        SHPPayload.Type3 payload3 = new SHPPayload.Type3(pbe);
        SHPPacket packet = new SHPPacket(header, payload3);
        System.out.println("sent msg3: " + packet + "\n");
        return packet;
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
