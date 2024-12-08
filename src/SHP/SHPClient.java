package SHP;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SHPClient {
    CryptoHandler cryptoHandler;
    Socket sock;
    InputStream in;
    OutputStream out;
    String host;
    int tcp_port;
    ClientECC clientECC;

    public SHPClient() { this("localhost", 3333); }

    public SHPClient(String host, int tcp_port) {
        this.cryptoHandler = new CryptoHandler();
        this.host = host;
        this.tcp_port = tcp_port;

        try {
            this.clientECC = parseClientECC();
            this.sock = new Socket(host, tcp_port);
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public void handshake(String userId, String password, String filename,
                          int udp_port) {
        try {
            System.out.println(clientECC);
            var oos = new ObjectOutputStream(out);

            // ---------------- MSG1 ----------------
            SHPPacket packet = prepareMessage1(userId);
            oos.writeObject(packet);

            // ---------------- MSG2 ----------------
            var ois = new ObjectInputStream(in);
            SHPPayload.Type2 payload2 = processMessage2(ois);

            // ---------------- MSG3 ----------------
            packet =
                prepareMessage3(userId, password, filename, udp_port, payload2);
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
                                      String filename, int udp_port,
                                      SHPPayload.Type2 payload2)
        throws Exception {
        byte[] pwHash = cryptoHandler.hashPassword(password);
        byte[] nonce4 = CryptoHandler.generateNonces(1);
        // TODO
        byte[] ydhClient = CryptoHandler.generateNonces(1);

        SHPEncryptedRequest encReq = new SHPEncryptedRequest(
            filename, userId, payload2.chall, nonce4, udp_port);
        byte[] pbe = cryptoHandler.encryptRequest(encReq, pwHash, payload2.salt,
                                                  payload2.counter);

        SHPSignedRequest sigReq = new SHPSignedRequest(
            filename, userId, payload2.chall, nonce4, udp_port, ydhClient);
        byte[] sig = cryptoHandler.signRequest(sigReq, pwHash, payload2.salt,
                                               payload2.counter);

        SHPHeader header = new SHPHeader(0x2, 0x1, 0x3);
        SHPPayload.Type3 payload3 = new SHPPayload.Type3(pbe, sig, ydhClient);
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

    private ClientECC parseClientECC() {
        try (BufferedReader reader =
                 new BufferedReader(new FileReader("ClientECCKeyPair.sec"))) {
            String curve = reader.readLine().split(":")[1].trim();

            String privKeyHex = reader.readLine().split(":")[1].trim();
            PrivateKey privKey = cryptoHandler.parsePrivateKeyHex(privKeyHex);

            String pubKeyHex = reader.readLine().split(":")[1].trim();
            PublicKey pubKey = cryptoHandler.parsePublicKeyHex(pubKeyHex);

            return new ClientECC(curve, privKey, pubKey);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private class ClientECC {
        String curve;
        PublicKey publicKey;
        PrivateKey privateKey;

        public ClientECC(String curve, PrivateKey privKey, PublicKey pubKey) {
            this.curve = curve;
            this.privateKey = privKey;
            this.publicKey = pubKey;
        }

        public String getCurve() { return curve; }

        public PublicKey getPublicKey() { return publicKey; }

        public PrivateKey getPrivateKey() { return privateKey; }

        @Override
        public String toString() {
            String privateKey = Utils.bytesToHex(this.privateKey.getEncoded());
            String publicKey = Utils.bytesToHex(this.publicKey.getEncoded());

            return "ClientECC [curve = " + this.curve +
                " | privateKey = " + privateKey +
                " | publicKey = " + publicKey + "]";
        }
    }
}
