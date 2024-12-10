package SHP;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CryptoConfig implements Serializable {
    private String confidentiality; // ALG/MODE/PADDING
    private String symmetricKey;    // in hex
    private int symmetricKeySize;   // in bits
    private Integer IVSize;         // int or NULL
    private String IV;              // hex or NULL
    private String integrity;       // HMAC or H
    private String hashFunction;    // secure hash func or NULL
    private String MAC;             // HMAC or CMAC
    private String MACKey;          // in hex or NULL
    private Integer MACKeySize;     // in bits

    // default config name
    public CryptoConfig() { this("cryptoconfig.txt"); }

    public CryptoConfig(String filename) { parseCryptoConfigFile(filename); }

    // professor, can we use a .props file next time? :(
    private void parseCryptoConfigFile(String filename) {
        try (BufferedReader reader =
                 new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                final String[] parts = line.split(":", 2);
                final String key = parts[0].trim();
                final String value = parts[1].trim();

                switch (key) {
                case "CONFIDENTIALITY":
                    this.confidentiality = value;
                    break;
                case "SYMMETRIC_KEY":
                    this.symmetricKey = value;
                    break;
                case "SYMMETRIC_KEY_SIZE":
                    this.symmetricKeySize = Integer.parseInt(value);
                    break;
                case "IV_SIZE":
                    this.IVSize =
                        value.equals("NULL") ? 0 : Integer.parseInt(value);
                    break;
                case "IV":
                    this.IV = value.equals("NULL") ? null : value;
                    break;
                case "INTEGRITY":
                    this.integrity = value;
                    break;
                case "H":
                    this.hashFunction = value.equals("NULL") ? null : value;
                    break;
                case "MAC":
                    this.MAC = value;
                    break;
                case "MACKEY":
                    this.MACKey = value.equals("NULL") ? null : value;
                    break;
                case "MACKEY_SIZE":
                    this.MACKeySize =
                        value.equals("NULL") ? 0 : Integer.parseInt(value);
                    break;
                }
            }
        } catch (final IOException e) {
            throw new RuntimeException("Error reading " + filename, e);
        }
    }

    public void setSymmetricKey(String symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public void setIV(String iV) { IV = iV; }

    public void setMACKey(String mACKey) { MACKey = mACKey; }

    //  from a couple of places
    // https://www.javatips.net/api/keywhiz-master/hkdf/src/main/java/keywhiz/hkdf/Hkdf.java
    // https://github.com/signalapp/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/kdf/HKDF.java
    // https://github.com/patrickfav/hkdf/blob/main/src/main/java/at/favre/lib/hkdf/HKDF.java 
    // https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/sun/security/ssl/HKDF.java
    private byte[] deriveBytes(Mac hkdf, byte[] secret, byte[] info, int length)
        throws Exception {
        hkdf.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] pseudoRand = hkdf.doFinal(new byte[32]);

        hkdf.init(new SecretKeySpec(pseudoRand, "HmacSHA256"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] prev = new byte[0];
        byte counter = 1;

        while (output.size() < length) {
            hkdf.reset();
            hkdf.update(prev);
            hkdf.update(info);
            hkdf.update(counter++);
            prev = hkdf.doFinal();
            output.write(prev);
        }

        return Arrays.copyOf(output.toByteArray(), length);
    }

    public void deriveKeysFromSecret(byte[] secretKey) throws Exception {
        Mac hkdf = Mac.getInstance("HmacSHA256", "BC");

        int symKeySize = this.getSymmetricKeySize();
        byte[] symKeyInfo = "SYMMETRIC_KEY".getBytes();
        setSymmetricKey(Utils.bytesToHex(
            deriveBytes(hkdf, secretKey, symKeyInfo, symKeySize / 8)));

        int ivSize = this.getIVSize();
        if (ivSize > 0) {
            byte[] ivInfo = "IV".getBytes();
            setIV(
                Utils.bytesToHex(deriveBytes(hkdf, secretKey, ivInfo, ivSize)));
        }

        int macKeySize = this.getMACKeySize();
        if (macKeySize > 0) {
            byte[] macKeyInfo = "MAC_KEY".getBytes();
            setMACKey(Utils.bytesToHex(
                deriveBytes(hkdf, secretKey, macKeyInfo, macKeySize / 8)));
        }
    }

    public boolean usesMAC() {
        return "HMAC".equals(this.integrity.toUpperCase()) ||
            "CMAC".equals(this.integrity.toUpperCase());
    }

    public boolean usesGMAC() {
        return this.MAC.toUpperCase().contains("GMAC");
    }

    public boolean usesGCM() {
        return this.confidentiality.toUpperCase().contains("GCM");
    }

    public boolean usesChaCha() {
        return this.confidentiality.toUpperCase().contains("CHACHA");
    }

    public String getConfidentiality() { return this.confidentiality; }

    public String getSymmetricKey() { return this.symmetricKey; }

    public byte[] getSymmetricKeyBytes() {
        return Utils.hexToBytes(this.symmetricKey);
    }

    public int getSymmetricKeySize() { return this.symmetricKeySize; }

    public int getIVSize() { return this.IVSize; }

    public String getIV() { return this.IV; }

    public byte[] getIVBytes() { return Utils.hexToBytes(this.IV); }

    public String getIntegrity() { return this.integrity; }

    public String getHashFunction() { return this.hashFunction; }

    public String getMAC() { return this.MAC; }

    public String getMACKey() { return this.MACKey; }

    public byte[] getMACKeyBytes() { return Utils.hexToBytes(this.MACKey); }

    public int getMACKeySize() { return this.MACKeySize; }

    public String summary() {
        return confidentiality + " | " + integrity + " | " +
            (usesMAC() ? MAC : hashFunction) + "\n";
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

    public static CryptoConfig deserialize(byte[] data) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais);) {

            return (CryptoConfig)ois.readObject();
        }
    }

    @Override
    public String toString() {
        return "CryptoConfig ["
            + "\n CONFIDENTIALITY = " + confidentiality +
            "\n SYMMETRIC_KEY = " + symmetricKey +
            "\n SYMMETRIC_KEY_SIZE = " + symmetricKeySize +
            "\n IV_SIZE = " + IVSize + "\n IV = " + IV +
            "\n INTEGRITY = " + integrity + "\n H = " + hashFunction +
            "\n MAC = " + MAC + "\n MACKEY = " + MACKey +
            "\n MACKEY_SIZE = " + MACKeySize + "\n]";
    }
}
