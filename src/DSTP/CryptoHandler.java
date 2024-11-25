package DSTP;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CryptoHandler
 */
public class CryptoHandler {
    private final CryptoConfig config;
    private Cipher cipher;
    private Mac MAC;
    private GMac GMAC;
    private MessageDigest hash;
    private SecretKey key;
    private IvParameterSpec ivSpec;

    public CryptoHandler() {
        this.config = new CryptoConfig("cryptoconfig.txt");
        init();
    }

    public CryptoHandler(String configfile) {
        this.config = new CryptoConfig(configfile);
        init();
    }
    
    @SuppressWarnings("deprecation")
    private void init() {
        Security.addProvider(new BouncyCastleProvider());
        Cipher ciphersuite;

        try {
            ciphersuite = Cipher.getInstance(config.getConfidentiality(), "BC");
        } catch (NoSuchAlgorithmException e) {
            ciphersuite = null;
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            ciphersuite = null;
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            ciphersuite = null;
            e.printStackTrace();
        }

        this.cipher = ciphersuite;

        this.key = new SecretKeySpec(config.getSymmetricKeyBytes(),
                                     config.getConfidentiality().split("/")[0]);

        if (config.getIV() != null) {
            if (config.usesGCM()) {
                this.ivSpec = null;
            } else {
                this.ivSpec = new IvParameterSpec(config.getIVBytes());
            }
        } else {
            this.ivSpec = null;
        }

        MessageDigest hash = null;
        try {
            if (config.usesMAC()) {
                if (config.usesGMAC()) {
                    if (config.getMAC().toUpperCase().contains("AES")) {
                        this.GMAC =
                            new GMac(new GCMBlockCipher(new AESEngine()));
                    } else if (config.getMAC().toUpperCase().contains("RC6")) {
                        this.GMAC =
                            new GMac(new GCMBlockCipher(new RC6Engine()));
                    } else {
                        throw new IllegalArgumentException("Unsupported GMAC");
                    }
                } else {
                    SecretKey macKey = new SecretKeySpec(
                        config.getMACKeyBytes(), config.getMAC());

                    this.MAC = Mac.getInstance(config.getMAC());
                    this.MAC.init(macKey);
                }
            } else {
                hash = MessageDigest.getInstance(config.getHashFunction());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        this.hash = hash;
    }

    public byte[] generateHash(byte[] data, short seqNr) {
        if (config.usesMAC()) {
            if (config.usesGMAC()) {
                KeyParameter keyParam =
                    new KeyParameter(config.getSymmetricKeyBytes());
                ParametersWithIV params =
                    new ParametersWithIV(keyParam, generateIVBytes(seqNr));

                GMAC.init(params);

                GMAC.update(data, 0, data.length);

                byte[] gmac = new byte[GMAC.getMacSize()];
                GMAC.doFinal(gmac, 0);

                return gmac;
            }

            return MAC.doFinal(data);
        }

        return hash.digest(data);
    }

    public boolean validateHash(byte[] hash, byte[] otherHash) {
        return MessageDigest.isEqual(hash, otherHash);
    }

    public int getHashLength() {
        if (config.usesMAC()) {
            if (config.usesGMAC()) {
                return GMAC.getMacSize();
            }
            return MAC.getMacLength();
        }

        return hash.getDigestLength();
    }

    private GCMParameterSpec generateGCMSpec(short seqNr) {
        return new GCMParameterSpec(config.getIVSize() * 8,
                                    generateIVBytes(seqNr));
    }

    private IvParameterSpec generateIVSpec(short seqNr) {
        return new IvParameterSpec(generateIVBytes(seqNr));
    }

    private byte[] generateIVBytes(short seqNr) {

        byte[] newIV = new byte[config.getIVSize()];
        System.arraycopy(config.getIVBytes(), 0, newIV, 0, 4);

        for (int i = 11; i >= 4; i--) {
            newIV[i] = (byte)(seqNr & 0xFF);
            seqNr >>>= 8;
        }

        return newIV;
    }

    public byte[] encrypt(byte[] data, short seqNr) throws Exception {
        if (this.ivSpec != null) {
            if (config.usesChaCha()) {
                this.ivSpec = generateIVSpec(seqNr);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        } else if (config.usesGCM()) {
            cipher.init(Cipher.ENCRYPT_MODE, key, generateGCMSpec(seqNr));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data, short seqNr) throws Exception {
        if (this.ivSpec != null) {
            if (config.usesChaCha()) {
                this.ivSpec = generateIVSpec(seqNr);
            }
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        } else if (config.usesGCM()) {
            cipher.init(Cipher.DECRYPT_MODE, key, generateGCMSpec(seqNr));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        return cipher.doFinal(data);
    }

    public String summary() { return config.summary(); }

    @Override
    public String toString() {
        return config.toString();
    }

    private class CryptoConfig {
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
        private CryptoConfig() { parseCryptoConfigFile("cryptoconfig.txt"); }

        private CryptoConfig(String filename) {
            parseCryptoConfigFile(filename);
        }

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
                        this.IVSize = value.equals("NULL")
                                          ? null
                                          : Integer.parseInt(value);
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
                        this.MACKeySize = value.equals("NULL")
                                              ? null
                                              : Integer.parseInt(value);
                        break;
                    }
                }
            } catch (final IOException e) {
                throw new RuntimeException("Error reading " + filename, e);
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

        @Override
        public String toString() {
            return "CryptoConfig [" +
                "\n CONFIDENTIALITY = " + confidentiality +
                "\n SYMMETRIC_KEY = " + symmetricKey +
                "\n SYMMETRIC_KEY_SIZE = " + symmetricKeySize +
                "\n IV_SIZE = " + IVSize +
                "\n IV = " + IV +
                "\n INTEGRITY = " + integrity +
                "\n H = " + hashFunction +
                "\n MAC = " + MAC +
                "\n MACKEY = " + MACKey +
                "\n MACKEY_SIZE = " + MACKeySize +
            "\n]";
        }
    }
}

