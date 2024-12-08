package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPSignedRequest implements Serializable {
    public String body;
    public String userId;
    public byte[] nonce3plus1;
    public byte[] nonce4;
    public int udp_port;
    public byte[] ydhClient;

    public SHPSignedRequest(String body, String userId, byte[] chall,
                            byte[] nonce4, int udp_port, byte[] ydhClient) {
        this.body = body;
        this.userId = userId;
        // TODO THIS PLUS 1
        this.nonce3plus1 = chall;
        this.nonce4 = nonce4;
        this.udp_port = udp_port;
        this.ydhClient = ydhClient;
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

    public static SHPSignedRequest deserialize(byte[] data) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPSignedRequest)ois.readObject();
        }
    }

    @Override
    public String toString() {
        return "SignedRequest [body= " + body + ", userId=" + userId +
            ", nonce3plus1=" + Utils.bytesToHex(nonce3plus1) +
            ", nonce4=" + Utils.bytesToHex(nonce4) +
            ", udp_port=" + udp_port +
            ", ydhClient=" + Utils.bytesToHex(ydhClient) + "]";
    }
}
