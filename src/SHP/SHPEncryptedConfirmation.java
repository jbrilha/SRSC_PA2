package SHP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SHPEncryptedConfirmation implements Serializable {
    public String body;
    public byte[] nonce4plus1;
    public byte[] nonce5;
    public byte[] config;

    public SHPEncryptedConfirmation(String body, byte[] nonce4plus1,
                                    byte[] nonce5, byte[] config) {
        this.body = body;
        this.nonce4plus1 = nonce4plus1;
        this.nonce5 = nonce5;
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

    public static SHPEncryptedConfirmation deserialize(byte[] data)
        throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (SHPEncryptedConfirmation)ois.readObject();
        }
    }

    @Override
    public String toString() {
        CryptoConfig cc = null;
		try {
			cc = CryptoConfig.deserialize(config);
		} catch (Exception e) {
			e.printStackTrace();
		}

        return "EncryptedConfirmation [body= " + body +
            ", nonce3plus1=" + Utils.bytesToHex(nonce4plus1) +
            ", nonce4=" + Utils.bytesToHex(nonce5) +
            ", config=" + cc + "]";
    }
}
