package SHP;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

public class SHPServer {
    Map<String, UserData> userDB;
    ServerSocket serverSock;
    Socket sock;
    InputStream in;
    OutputStream out;
    int port;

    public SHPServer() {
        this(3333);
    }

    public SHPServer(int port) {
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

    public String handshake() throws IllegalAccessException {
        try {
            SHPPacket packet = SHPPacket.fromInputStream(in);
            SHPPayload payload = packet.getPayload();
            String userID =
                new String(payload.getData(), 0, payload.getDataLength()).trim();
            System.out.println("rec msg1: " + packet + "\n");

            if (!userDB.keySet().contains(userID)) {
                throw new IllegalAccessException(
                        "User is not registered in the system");
            }
            System.out.println(userID + ": " + userDB.get(userID));

            SHPHeader header = new SHPHeader(0x1, 0x1, 0x2);
            byte[] nonces = generateNonces(3);
            String noncesStr = Hex.toHexString(nonces);
            System.out.println("nonces: " + noncesStr);
            payload = new SHPPayload(nonces);
            packet = new SHPPacket(header, payload);
            System.out.println("sent msg2: " + packet + "\n");
            out.write(packet.toByteArray());

            packet = SHPPacket.fromInputStream(in);
            payload = packet.getPayload();
            header = packet.getHeader();
            String request = new String(payload.getData(), 0, payload.getDataLength());
            return request;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] generateNonces(int count) {
        SecureRandom r = new SecureRandom();
        byte[] nonces = new byte[16 * count];
        
        r.nextBytes(nonces);

        return nonces;
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
        try (BufferedReader reader = new BufferedReader(new FileReader("userdatabase.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                final String[] fields = line.split(":", 4);
                final String userID = fields[0].trim();
                final byte[] pwHash = Utils.hexToBytes(fields[1].trim());
                final byte[] salt = Utils.hexToBytes(fields[2].trim());
                final byte[] key = Utils.hexToBytes(fields[3].trim());

                userDB.put(userID, new UserData(pwHash, salt, key));
            }

            for (var kv : userDB.entrySet()) {
                System.out.println(kv);
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

        public byte[] getPasswordHash() {
            return passwordHash;
        }

        public void setPasswordHash(byte[] passwordHash) {
            this.passwordHash = passwordHash;
        }

        public byte[] getSalt() {
            return salt;
        }

        public void setSalt(byte[] salt) {
            this.salt = salt;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }

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
