package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPEncryptedRequest implements Serializable {
    public String body;
    public String userId;
    public byte[] nonce3plus1;
    public byte[] nonce4;
    public int udp_port;

    public SHPEncryptedRequest(String body, String userId, byte[] chall,
                               byte[] nonce4, int udp_port) {
        this.body = body;
        this.userId = userId;
        // TODO THIS PLUS 1
        this.nonce3plus1 = chall;
        this.nonce4 = nonce4;
        this.udp_port = udp_port;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(this);
            return baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    public static SHPEncryptedRequest deserialize(byte[] data)
        throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPEncryptedRequest)ois.readObject();
        }
    }

    @Override
    public String toString() {
        return "EncryptedRequest [body= " + body + ", userId=" + userId +
            ", nonce3plus1=" + Utils.bytesToHex(nonce3plus1) +
            ", nonce4=" + Utils.bytesToHex(nonce4) +
            ", udp_port=" + udp_port + "]";
    }
}
