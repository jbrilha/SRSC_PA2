package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPRequest implements Serializable {
    public String body;
    public CryptoConfig config;
    public int udp_port;

    public SHPRequest(String body, CryptoConfig cc, int udp_port) {
        this.body = body;
        this.config = cc;
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

    public static SHPRequest deserialize(byte[] data)
        throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPRequest)ois.readObject();
        }
    }

    @Override
    public String toString() {
        return "Request [body= " + body +
            ", condfig=" + config +
            ", udp_port=" + udp_port + "]";
    }
}
