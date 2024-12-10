package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPEncryptedGreenlight implements Serializable {
    public String body;
    public byte[] nonce5plus1;

    public SHPEncryptedGreenlight(String body, byte[] nonce5plus1) {
        this.body = body;
        this.nonce5plus1 = nonce5plus1;
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

    public static SHPEncryptedGreenlight deserialize(byte[] data)
            throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
                ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPEncryptedGreenlight) ois.readObject();
        }
    }

    @Override
    public String toString() {
        return "EncryptedGreenlight [body= " + body +
                ", nonce5plus1=" + Utils.bytesToHex(nonce5plus1) + "]";
    }
}
