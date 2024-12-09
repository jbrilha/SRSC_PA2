package SHP;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.PublicKey;

public class SHPClient {
    CryptoHandler cryptoHandler;
    Socket sock;
    InputStream in;
    OutputStream out;
    String host;
    int tcp_port;
    ECConfig clientECC;
    PublicKey serverPubKey;

    public SHPClient() { this("localhost", 3333); }

    public SHPClient(String host, int tcp_port) {
        this.cryptoHandler = new CryptoHandler();
        this.host = host;
        this.tcp_port = tcp_port;

        try {
            this.clientECC =
                ECConfig.parseConfigFile("ClientECCKeyPair.sec", cryptoHandler);
            this.serverPubKey = parseServerKey();
            this.sock = new Socket(host, tcp_port);
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public CryptoConfig handshake(String userId, String password,
                                  String filename, int udp_port) {
        try {
            byte[] pwHash = cryptoHandler.hashPassword(password);
            var oos = new ObjectOutputStream(out);

            // ---------------- MSG1 ----------------
            SHPPacket packet = prepareMessage1(userId);
            oos.writeObject(packet);

            // ---------------- MSG2 ----------------
            var ois = new ObjectInputStream(in);
            SHPPayload.Type2 payload2 = processMessage2(ois);

            // ---------------- MSG3 ----------------
            packet =
                prepareMessage3(userId, pwHash, filename, udp_port, payload2);
            oos.writeObject(packet);

            // ---------------- MSG4 ----------------
            SHPPayload.Type4 payload4 = processMessage4(ois);
            SHPEncryptedConfirmation confirmation =
                validateConfirmation(userId, pwHash, payload4);
            System.out.println(confirmation);

            // ---------------- MSG5 ----------------
            String oi = "oi";
            oos.writeObject(oi);

            ois.close();
            oos.close();
            destroy();
            return CryptoConfig.deserialize(confirmation.config);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private SHPEncryptedConfirmation
    validateConfirmation(String userId, byte[] pwHash,
                         SHPPayload.Type4 payload4) throws Exception {
        boolean validAuth = cryptoHandler.validateAuth(
            pwHash, payload4.envelope, payload4.ydhServer, payload4.signature,
            payload4.authCode);
        if (!validAuth) {
            throw new IllegalAccessException();
        }
        SHPEncryptedConfirmation confirmation =
            cryptoHandler.decryptConfirmation(payload4.envelope,
                                              clientECC.getPrivateKey());
        SHPSignedConfirmation sigReq =
            SHPSignedConfirmation.fromEncryptedConfirmation(
                confirmation, userId, payload4.ydhServer);
        boolean validSign = cryptoHandler.validateSignature(
            sigReq, payload4.signature, serverPubKey);

        if (!validSign) {
            throw new IllegalAccessException();
        }

        return confirmation;
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

    private SHPPacket prepareMessage3(String userId, byte[] pwHash,
                                      String filename, int udp_port,
                                      SHPPayload.Type2 payload2)
        throws Exception {
        byte[] nonce4 = CryptoHandler.generateNonces(1);
        byte[] ydhClient = cryptoHandler.generateDHPubKey();
        // System.out.println("\n\nydhclient: " + Utils.bytesToHex(ydhClient));

        SHPEncryptedRequest encReq = new SHPEncryptedRequest(
            filename, userId, payload2.chall, nonce4, udp_port);
        byte[] pbe = cryptoHandler.encryptRequest(encReq, pwHash, payload2.salt,
                                                  payload2.counter);

        SHPSignedRequest sigReq = new SHPSignedRequest(
            filename, userId, payload2.chall, nonce4, udp_port, ydhClient);
        byte[] sig =
            cryptoHandler.signRequest(sigReq, clientECC.getPrivateKey());

        byte[] authCode =
            cryptoHandler.authenticateRequest(pwHash, pbe, ydhClient, sig);

        SHPHeader header = new SHPHeader(0x2, 0x1, 0x3);
        SHPPayload.Type3 payload3 =
            new SHPPayload.Type3(pbe, ydhClient, sig, authCode);
        SHPPacket packet = new SHPPacket(header, payload3);
        System.out.println("sent msg3: " + packet + "\n");
        return packet;
    }

    private SHPPayload.Type4 processMessage4(ObjectInputStream ois)
        throws Exception {
        SHPPacket packet = (SHPPacket)ois.readObject();
        SHPPayload.Type4 payload4 = (SHPPayload.Type4)packet.getPayload();
        // TODO check header msg type
        // header = packet.getHeader();
        System.out.println("rec msg4: " + packet + "\n");
        return payload4;
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

    private PublicKey parseServerKey() {
        try (BufferedReader reader =
                 new BufferedReader(new FileReader("ServerECCPubKey.txt"))) {
            String curve = reader.readLine().split(":")[1].trim();

            String pubKeyHex = reader.readLine().split(":")[1].trim();
            return cryptoHandler.parsePublicKeyHex(pubKeyHex);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String toString() {
        String serverKey = Utils.bytesToHex(this.serverPubKey.getEncoded());
        return "SHPClient [sock = " + sock.getInetAddress() +
            " | serverPubKey = " + serverKey + "]";
    }
}
