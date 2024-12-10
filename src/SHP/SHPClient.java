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

    public SHPClient() {
        this("localhost", 3333);
    }

    public SHPClient(String host, int tcp_port) {
        this.cryptoHandler = new CryptoHandler();
        this.host = host;
        this.tcp_port = tcp_port;

        try {
            this.clientECC = ECConfig.parseConfigFile("ClientECCKeyPair.sec", cryptoHandler);
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
            packet = prepareMessage3(userId, pwHash, filename, udp_port, payload2);
            SHPPayload.Type3 payload3 = (SHPPayload.Type3) packet.getPayload();
            oos.writeObject(packet);

            // ---------------- MSG4 ----------------
            SHPPayload.Type4 payload4 = processMessage4(ois);
            SHPEncryptedConfirmation confirmation = validateConfirmation(userId, pwHash, payload4);
            byte[] secretKey = cryptoHandler.generateSharedSecret(payload4.ydhServer);

            // ---------------- MSG5 ----------------
            packet = prepareMessage5(confirmation.nonce5, secretKey);
            oos.writeObject(packet);

            ois.close();
            oos.close();
            destroy();
            CryptoConfig cc = CryptoConfig.deserialize(confirmation.config);
            cc.deriveKeysFromSecret(secretKey);
            return cc;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private SHPEncryptedConfirmation validateConfirmation(String userId, byte[] pwHash,
            SHPPayload.Type4 payload4) throws Exception {
        boolean validAuth = cryptoHandler.validateMAC(
                pwHash, payload4.authCode, payload4.envelope, payload4.ydhServer,
                payload4.signature);
        if (!validAuth) {
            throw new IllegalAccessException();
        }
        var confirmation = SHPEncryptedConfirmation.deserialize(
                cryptoHandler.performAssymetricDecryption(
                        payload4.envelope, clientECC.getPrivateKey()));
        SHPSignedConfirmation sigReq = SHPSignedConfirmation.fromEncryptedConfirmation(
                confirmation, userId, payload4.ydhServer);
        boolean validSign = cryptoHandler.validateSignature(
                serverPubKey, payload4.signature, sigReq.serialize());

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
        SHPPacket packet = (SHPPacket) ois.readObject();
        SHPPayload.Type2 payload2 = (SHPPayload.Type2) packet.getPayload();
        // TODO better handling
        if (packet.getHeader().getMsgType() != 2)
            throw new IllegalAccessException();
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
        byte[] pbe = cryptoHandler.performPasswordEncryption(
                encReq.serialize(), pwHash, payload2.salt, payload2.counter);

        SHPSignedRequest sigReq = new SHPSignedRequest(
                filename, userId, payload2.chall, nonce4, udp_port, ydhClient);
        byte[] sig = cryptoHandler.generateSignature(clientECC.getPrivateKey(),
                sigReq.serialize());

        byte[] authCode = cryptoHandler.generateMAC(pwHash, pbe, ydhClient, sig);

        SHPHeader header = new SHPHeader(0x2, 0x1, 0x3);
        SHPPayload.Type3 payload3 = new SHPPayload.Type3(pbe, ydhClient, sig, authCode);
        SHPPacket packet = new SHPPacket(header, payload3);
        System.out.println("sent msg3: " + packet + "\n");
        return packet;
    }

    private SHPPayload.Type4 processMessage4(ObjectInputStream ois)
            throws Exception {
        SHPPacket packet = (SHPPacket) ois.readObject();
        SHPPayload.Type4 payload4 = (SHPPayload.Type4) packet.getPayload();
        // TODO better handling
        if (packet.getHeader().getMsgType() != 4)
            throw new IllegalAccessException();
        System.out.println("rec msg4: " + packet + "\n");
        return payload4;
    }

    private SHPPacket prepareMessage5(byte[] nonce5, byte[] secretKey)
            throws Exception {
        // TODO
        byte[] nonce5plus1 = CryptoHandler.generateNonces(1);
        var greenlight = new SHPEncryptedGreenlight("GO", nonce5plus1);
        byte[] encGl = cryptoHandler.performSymetricEncryption(
                greenlight.serialize(), secretKey);
        byte[] authCode = cryptoHandler.generateMAC(secretKey, encGl);

        SHPHeader header = new SHPHeader(0x2, 0x1, 0x5);
        SHPPayload.Type5 payload5 = new SHPPayload.Type5(encGl, authCode);
        SHPPacket packet = new SHPPacket(header, payload5);

        System.out.println("sent msg5: " + packet + "\n");
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

    private PublicKey parseServerKey() {
        try (BufferedReader reader = new BufferedReader(new FileReader("ServerECCPubKey.txt"))) {
            String curve = reader.readLine().split(":")[1].trim();

            String pubKeyHex = reader.readLine().split(":")[1].trim();
            return cryptoHandler.parseECPublicKeyHex(pubKeyHex);
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
