package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPSignedConfirmation implements Serializable {
    public String body;
    public String userId;
    public byte[] nonce4plus1;
    public byte[] config;
    public byte[] ydhServer;

    public SHPSignedConfirmation(String body, String userId, byte[] nonce4plus1,
                                 byte[] config, byte[] ydhServer) {
        this.body = body;
        this.userId = userId;
        // TODO THIS PLUS 1
        this.nonce4plus1 = nonce4plus1;
        this.ydhServer = ydhServer;
        this.config = config;
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

    public static SHPSignedConfirmation deserialize(byte[] data)
        throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPSignedConfirmation)ois.readObject();
        }
    }

    public static SHPSignedConfirmation
    fromEncryptedConfirmation(SHPEncryptedConfirmation conf, String userId,
                         byte[] ydhServer) {
        return new SHPSignedConfirmation(conf.body, userId, conf.nonce4plus1,
                                         conf.config, ydhServer);
    }

    @Override
    public String toString() {
        return "SignedRequest [body= " + body + ", userId=" + userId +
            ", nonce4plus1=" + Utils.bytesToHex(nonce4plus1) +
            ", config=" + Utils.bytesToHex(config) +
            ", ydhServer=" + Utils.bytesToHex(ydhServer) + "]";
    }
}
