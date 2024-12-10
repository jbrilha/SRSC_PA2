package SHP;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class CryptoConfig implements Serializable {
    private String confidentiality;     // ALG/MODE/PADDING
    private String symmetricKey = null; // in hex
    private int symmetricKeySize;       // in bits
    private Integer IVSize;             // int or NULL
    private String IV = null;           // hex or NULL
    private String integrity;           // HMAC or H
    private String hashFunction;        // secure hash func or NULL
    private String MAC;                 // HMAC or CMAC
    private String MACKey = null;       // in hex or NULL
    private Integer MACKeySize;         // in bits

    // default config name
    public CryptoConfig() { this("ciphersuite.conf"); }

    public CryptoConfig(String filename) { parseCryptoConfigFile(filename); }

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
                // case "SYMMETRIC_KEY":
                //     this.symmetricKey = value;
                //     break;
                case "SYMMETRIC_KEY_SIZE":
                    this.symmetricKeySize = Integer.parseInt(value);
                    break;
                case "IV_SIZE":
                    this.IVSize =
                        value.equals("NULL") ? 0 : Integer.parseInt(value);
                    break;
                // case "IV":
                //     this.IV = value.equals("NULL") ? null : value;
                //     break;
                case "INTEGRITY":
                    this.integrity = value;
                    break;
                case "H":
                    this.hashFunction = value.equals("NULL") ? null : value;
                    break;
                case "MAC":
                    this.MAC = value;
                    break;
                // case "MACKEY":
                //     this.MACKey = value.equals("NULL") ? null : value;
                //     break;
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

    public void setMACKey(String macKey) { MACKey = macKey; }

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
