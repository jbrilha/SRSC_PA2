package SHP;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;

public class SHPServer {
    CryptoHandler cryptoHandler;
    Map<String, UserData> userDB;
    ServerSocket serverSock;
    Socket sock;
    InputStream in;
    OutputStream out;
    int port;

    public SHPServer() { this(3333); }

    public SHPServer(int port) {
        this.cryptoHandler = new CryptoHandler();
        this.port = port;
        this.userDB = new HashMap<>();
        parseUserDB();

        try {
            this.serverSock = new ServerSocket(port);
            this.sock = serverSock.accept();
            this.in = sock.getInputStream();
            this.out = sock.getOutputStream();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }
    // public void sendResponse() throws IllegalAccessException {}

    public SHPEncryptedRequest receiveRequest() throws IllegalAccessException {
        try {
            var ois = new ObjectInputStream(in);

            // ---------------- MSG1 ----------------
            // SHPPacket packet = SHPPacket.fromInputStream(in);
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
            SHPPacket packet = prepareMessage2(salt, counter, chall);
            oos.writeObject(packet);

            // ---------------- MSG3 ----------------
            SHPPayload.Type3 payload3 = processMessage3(ois);
            SHPEncryptedRequest request = cryptoHandler.decryptRequest(
                payload3.PBE, user.getPasswordHash(), salt, counter);
            System.out.println("req: " + request.request);

            ois.close();
            oos.close();
            return request;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private SHPPayload.Type1 processMessage1(ObjectInputStream ois)
        throws Exception {
        SHPPacket packet = (SHPPacket)ois.readObject();
        SHPPayload.Type1 payload1 = (SHPPayload.Type1)packet.getPayload();
        // TODO check header msg type
        // header = packet.getHeader();
        System.out.println("rec msg1: " + packet + "\n");
        return payload1;
    }
    private SHPPayload.Type3 processMessage3(ObjectInputStream ois)
        throws Exception {
        SHPPacket packet = (SHPPacket)ois.readObject();
        SHPPayload.Type3 payload3 = (SHPPayload.Type3)packet.getPayload();
        // TODO check header msg type
        // header = packet.getHeader();
        System.out.println("rec msg3: " + packet + "\n");
        return payload3;
    }


    private SHPPacket prepareMessage2(byte[] salt, byte[] counter, byte[] chall)
        throws Exception {
        SHPHeader header = new SHPHeader(0x2, 0x1, 0x2);
        SHPPayload.Type2 payload2 = new SHPPayload.Type2(salt, counter, chall);
        SHPPacket packet = new SHPPacket(header, payload2);
        System.out.println("sent msg2: " + packet + "\n");
        return packet;
    }

    public void sendConfirmation(byte[] nonce4) {
        try {

            var oos = new ObjectOutputStream(out);
            // ---------------- MSG2 ----------------
            SHPHeader header = new SHPHeader(0x2, 0x1, 0x2);
            byte[] nonce5 = CryptoHandler.generateNonces(1);

            // SHPPayload.Type4 payload2 =
            // new SHPPayload.Type2(salt, counter, chall);
            // packet = new SHPPacket(header, payload2);
            // System.out.println("sent msg2: " + packet + "\n");
            // oos.writeObject(packet);

            // // packet = SHPPacket.fromInputStream(in);
            // packet = (SHPPacket)ois.readObject();
            // payload = packet.getPayload();
            // header = packet.getHeader();
            // String request =
            // new String(payload.getData(), 0, payload.getDataLength());
            //
        } catch (Exception e) {
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

    private void parseUserDB() {
        try (BufferedReader reader =
                 new BufferedReader(new FileReader("userdatabase.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                final String[] fields = line.split(":", 4);
                final String userID = fields[0].trim();
                final byte[] pwHash = Utils.hexToBytes(fields[1].trim());
                final byte[] salt = Utils.hexToBytes(fields[2].trim());
                final byte[] key = Utils.hexToBytes(fields[3].trim());

                userDB.put(userID, new UserData(pwHash, salt, key));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class UserData {
        byte[] passwordHash;
        byte[] salt;
        byte[] publicKey;

        public UserData(byte[] pwHash, byte[] salt, byte[] key) {
            this.passwordHash = pwHash;
            this.salt = salt;
            this.publicKey = key;
        }

        public byte[] getPasswordHash() { return passwordHash; }

        public void setPasswordHash(byte[] passwordHash) {
            this.passwordHash = passwordHash;
        }

        public byte[] getSalt() { return salt; }

        public void setSalt(byte[] salt) { this.salt = salt; }

        public byte[] getPublicKey() { return publicKey; }

        public void setPublicKey(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public String toString() {
            String passwordHash = Utils.bytesToHex(this.passwordHash);
            String salt = Utils.bytesToHex(this.salt);
            String publicKey = Utils.bytesToHex(this.publicKey);

            return "UserData [passwordHash = " + passwordHash +
                " | salt = " + salt + " | publicKey = " + publicKey + "]";
        }
    }
}
