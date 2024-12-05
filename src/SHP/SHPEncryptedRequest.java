package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPEncryptedRequest implements Serializable {
    public String request;
    public String userId;
    public byte[] nonce3plus1;
    public byte[] nonce4;
    public int udp_port;

    public SHPEncryptedRequest(String request, String userId, byte[] chall,
                      byte[] nonce4, int udp_port) {
        this.request = request;
        this.userId = userId;
        this.nonce3plus1 = chall;
        this.nonce4 = nonce4;
        this.udp_port = udp_port;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos);

        ) {
            oos.writeObject(this);
            return baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    public static SHPEncryptedRequest deserialize(byte[] data) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPEncryptedRequest) ois.readObject();
        }
    }
}
