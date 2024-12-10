package SHP;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class SHPServer {
    boolean showMessages = false;
    CryptoHandler cryptoHandler;
    Map<String, UserData> userDB;
    ServerSocket serverSock;
    public Socket sock;
    InputStream in;
    OutputStream out;
    int port;
    ECConfig serverECC;

    public SHPServer() {
        this(3333);
    }

    public SHPServer(int port) {
        this.cryptoHandler = new CryptoHandler();
        this.port = port;
        this.userDB = new HashMap<>();
        parseUserDB();

        try {
            this.serverECC = ECConfig.parseConfigFile("ServerECCKeyPair.sec", cryptoHandler);
            this.serverSock = new ServerSocket(port);
            this.sock = serverSock.accept();
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    public SHPRequest handshake() throws IllegalAccessException {
        try {
            var ois = new ObjectInputStream(in);

            // ---------------- MSG1 ----------------
            SHPPayload.Type1 payload1 = processMessage1(ois);
            String userID = payload1.getUserId();

            UserData user = userDB.get(userID);
            if (user == null) {
                throw new IllegalAccessException(
                        "User is not registered in the system");
            }

            // ---------------- MSG2 ----------------
            byte[] nonces = CryptoHandler.generateNonces(3);
            ByteBuffer nonceBuffer = ByteBuffer.wrap(nonces, 0, nonces.length);
            byte[] salt = new byte[16];
            byte[] counter = new byte[16];
            byte[] chall = new byte[16];
            nonceBuffer.get(salt);
            nonceBuffer.get(counter);
            nonceBuffer.get(chall);

            var oos = new ObjectOutputStream(out);
            sendMessage2(oos, salt, counter, chall);

            // ---------------- MSG3 ----------------
            SHPPayload.Type3 payload3 = processMessage3(ois);
            SHPEncryptedRequest request = validateRequest(user, payload3, salt, counter, chall);

            // ---------------- MSG4 ----------------
            byte[] nonce5 = CryptoHandler.generateNonces(1);
            CryptoConfig cc = new CryptoConfig();
            sendMessage4(oos, user, cc, request.nonce4, nonce5);

            byte[] secret = cryptoHandler.generateSharedSecret(payload3.ydhClient);
            // ---------------- MSG5 ----------------
            SHPPayload.Type5 payload5 = processMessage5(ois);
            validateGreenlight(secret, payload5, nonce5);

            ois.close();
            oos.close();
            destroy();

            cryptoHandler.updateCiphersuite(cc, secret);
            return new SHPRequest(request.body, cc, request.udp_port);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void validateGreenlight(byte[] secret, SHPPayload.Type5 payload5,
            byte[] nonce5) throws Exception {
        byte[] secretKey = cryptoHandler.deriveKeyFromSecret(
                32, "SYMMETRIC_KEY".getBytes(), secret);
        boolean validAuth = cryptoHandler.validateMAC(
                secretKey, payload5.authCode, payload5.greenlight);
        if (!validAuth) {
            throw new IllegalAccessException();
        }

        var greenlight = SHPEncryptedGreenlight.deserialize(
                cryptoHandler.performSymetricDecryption(payload5.greenlight,
                        secretKey));
        if (!greenlight.body.equals("GO")) {
            throw new IllegalAccessException("Unexpected greenlight message");
        }

        boolean validChall = CryptoHandler.validateChallenge(greenlight.nonce5plus1, nonce5);
        if (!validChall) {
            throw new IllegalAccessException("Invalid challenge");
        }
    }

    private SHPPayload.Type1 processMessage1(ObjectInputStream ois)
            throws Exception {
        SHPPacket packet = (SHPPacket) ois.readObject();
        SHPPayload.Type1 payload1 = (SHPPayload.Type1) packet.getPayload();

        int msgType = packet.getHeader().getMsgType();
        if (msgType != 1)
            throw new IllegalAccessException(String.format(
                    "Invalid message type. Expected : %d | Receieved: %d", 1,
                    msgType));

        if (showMessages)
            System.out.println("rec msg1: " + packet + "\n");

        return payload1;
    }

    private void sendMessage2(ObjectOutputStream oos, byte[] salt,
            byte[] counter, byte[] chall) throws Exception {
        SHPHeader header = new SHPHeader(0x2, 0x1, 0x2);
        SHPPayload.Type2 payload2 = new SHPPayload.Type2(salt, counter, chall);
        SHPPacket packet = new SHPPacket(header, payload2);

        if (showMessages)
            System.out.println("sent msg2: " + packet + "\n");

        oos.writeObject(packet);
    }

    private SHPPayload.Type3 processMessage3(ObjectInputStream ois)
            throws Exception {
        SHPPacket packet = (SHPPacket) ois.readObject();
        SHPPayload.Type3 payload3 = (SHPPayload.Type3) packet.getPayload();

        int msgType = packet.getHeader().getMsgType();
        if (msgType != 3)
            throw new IllegalAccessException(String.format(
                    "Invalid message type. Expected : %d | Receieved: %d", 3,
                    msgType));

        if (showMessages)
            System.out.println("rec msg3: " + packet + "\n");

        return payload3;
    }

    private void sendMessage4(ObjectOutputStream oos, UserData user,
            CryptoConfig cryptoConfig, byte[] nonce4,
            byte[] nonce5) throws Exception {
        byte[] ydhServer = cryptoHandler.generateDHPubKey();
        byte[] nonce4plus1 = CryptoHandler.generateChallenge(nonce4);
        byte[] config = cryptoConfig.serialize();
        String confirmation = "confirmed";

        SHPEncryptedConfirmation encConf = new SHPEncryptedConfirmation(
                confirmation, nonce4plus1, nonce5, config);
        byte[] encEnvelope = cryptoHandler.performAssymetricEncryption(
                encConf.serialize(), user.getPublicKey());

        SHPSignedConfirmation sigConf = new SHPSignedConfirmation(
                confirmation, user.getUserID(), nonce4plus1, config, ydhServer);
        byte[] sig = cryptoHandler.generateSignature(serverECC.getPrivateKey(),
                sigConf.serialize());

        byte[] authCode = cryptoHandler.generateMAC(
                user.getPasswordHash(), encEnvelope, ydhServer, sig);

        SHPHeader header = new SHPHeader(0x2, 0x1, 0x4);
        SHPPayload.Type4 payload4 = new SHPPayload.Type4(encEnvelope, ydhServer, sig, authCode);
        SHPPacket packet = new SHPPacket(header, payload4);

        if (showMessages)
            System.out.println("sent msg4: " + packet + "\n");

        oos.writeObject(packet);
    }

    private SHPPayload.Type5 processMessage5(ObjectInputStream ois)
            throws Exception {
        SHPPacket packet = (SHPPacket) ois.readObject();
        SHPPayload.Type5 payload5 = (SHPPayload.Type5) packet.getPayload();

        int msgType = packet.getHeader().getMsgType();
        if (msgType != 5)
            throw new IllegalAccessException(String.format(
                    "Invalid message type. Expected : %d | Receieved: %d", 5,
                    msgType));

        if (showMessages)
            System.out.println("rec msg5: " + packet + "\n");

        return payload5;
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

    private SHPEncryptedRequest validateRequest(UserData user, SHPPayload.Type3 payload3, byte[] salt,
            byte[] counter, byte[] nonce3) throws Exception {
        boolean validAuth = cryptoHandler.validateMAC(
                user.getPasswordHash(), payload3.authCode, payload3.pbe,
                payload3.ydhClient, payload3.signature);
        if (!validAuth) {
            throw new IllegalAccessException("Invalid HMAC");
        }
        var request = SHPEncryptedRequest.deserialize(
                cryptoHandler.performPasswordDecryption(
                        payload3.pbe, user.getPasswordHash(), salt, counter));
        SHPSignedRequest sigReq = SHPSignedRequest.fromEncryptedRequest(request, payload3.ydhClient);

        boolean validChall = CryptoHandler.validateChallenge(sigReq.nonce3plus1, nonce3);
        if (!validChall) {
            throw new IllegalAccessException("Invalid challenge");
        }

        boolean validSign = cryptoHandler.validateSignature(
                user.getPublicKey(), payload3.signature, sigReq.serialize());

        if (!validSign) {
            throw new IllegalAccessException("Invalid signature");
        }
        if (!(request.body.equals("cars.dat") ||
                request.body.equals("monsters.dat"))) {
            throw new FileNotFoundException(request.body);
        }

        return request;
    }

    private void parseUserDB() {
        try (BufferedReader reader = new BufferedReader(new FileReader("userdatabase.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                final String[] fields = line.split(":", 4);
                final String userID = fields[0].trim();
                final byte[] pwHash = Utils.hexToBytes(fields[1].trim());
                final byte[] salt = Utils.hexToBytes(fields[2].trim());
                final PublicKey key = cryptoHandler.parseECPublicKeyHex(fields[3].trim());

                userDB.put(userID, new UserData(userID, pwHash, salt, key));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class UserData {
        String userID;
        byte[] passwordHash;
        byte[] salt;
        PublicKey publicKey;

        public UserData(String userID, byte[] pwHash, byte[] salt,
                PublicKey key) {
            this.userID = userID;
            this.passwordHash = pwHash;
            this.salt = salt;
            this.publicKey = key;
        }

        public String getUserID() {
            return userID;
        }

        public byte[] getPasswordHash() {
            return passwordHash;
        }

        public byte[] getSalt() {
            return salt;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        @Override
        public String toString() {
            String passwordHash = Utils.bytesToHex(this.passwordHash);
            String salt = Utils.bytesToHex(this.salt);
            String publicKey = Utils.bytesToHex(this.publicKey.getEncoded());

            return "UserData [userID = " + userID +
                    " | passwordHash = " + passwordHash + " | salt = " + salt +
                    " | publicKey = " + publicKey + "]";
        }
    }
}
