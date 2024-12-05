package SHP;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CryptoHandler
 */
public class CryptoHandler {
    private MessageDigest hash;
    private Mac mac;
    private Signature signature;
    private Cipher pwCipher;
    private Cipher confCipher;
    private SecretKeyFactory keyFactory;

    public CryptoHandler() {
        Security.addProvider(new BouncyCastleProvider());

        try {
            this.hash = MessageDigest.getInstance("SHA256", "BC");
            this.mac = Mac.getInstance("HMAC-SHA512", "BC");
            this.signature = Signature.getInstance("SHA256withECDSA", "BC");
            this.pwCipher =
                Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
            this.keyFactory = SecretKeyFactory.getInstance(
                "PBEWITHSHA256AND192BITAES-CBC-BC", "BC");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public byte[] encryptRequest(SHPEncryptedRequest request, byte[] password,
                                 byte[] salt, byte[] counter) throws Exception {
        System.out.println("client pw: " + Utils.bytesToHex(password));
        String pwHex = Utils.bytesToHex(password);
        PBEKeySpec pwSpec = new PBEKeySpec(pwHex.toCharArray());
        Key sKey = keyFactory.generateSecret(pwSpec);
        String counterStr = Utils.bytesToHex(counter);
        BigInteger counterInt = new BigInteger(counterStr, 16);

        // TODO FIX COUNTER
        pwCipher.init(Cipher.ENCRYPT_MODE, sKey,
                      new PBEParameterSpec(salt, 2048));

        return pwCipher.doFinal(request.serialize());
    }

    public SHPEncryptedRequest decryptRequest(byte[] request, byte[] password,
                                     byte[] salt, byte[] counter)
        throws Exception {
        System.out.println("server pw: " + Utils.bytesToHex(password));
        String pwHex = Utils.bytesToHex(password);
        PBEKeySpec pwSpec = new PBEKeySpec(pwHex.toCharArray());
        Key sKey = keyFactory.generateSecret(pwSpec);
        String counterStr = Utils.bytesToHex(counter);
        BigInteger counterInt = new BigInteger(counterStr, 16);

        // TODO FIX COUNTER
        pwCipher.init(Cipher.DECRYPT_MODE, sKey,
                      new PBEParameterSpec(salt, 2048));

        return SHPEncryptedRequest.deserialize(pwCipher.doFinal(request));
    }

    public void signRequest() {}

    public boolean validatePassword(byte[] received, byte[] expected) {
        return MessageDigest.isEqual(received, expected);
    }

    public byte[] hashPassword(String password) {
        hash.update(password.getBytes());
        return hash.digest();
    }

    public static byte[] generateNonces(int count) {
        SecureRandom r = new SecureRandom();
        byte[] nonces = new byte[16 * count];

        r.nextBytes(nonces);

        return nonces;
    }

    // private final CryptoConfig config;
    // private Cipher cipher;
    // private Mac MAC;
    // private GMac GMAC;
    // private MessageDigest hash;
    // private SecretKey key;
    // private IvParameterSpec ivSpec;
    //
    // public CryptoHandler() {
    // this.config = new CryptoConfig("cryptoconfig.txt");
    // init();
    // }
    //
    // public CryptoHandler(String configfile) {
    // this.config = new CryptoConfig(configfile);
    // init();
    // }
    //
    // @SuppressWarnings("deprecation")
    // private void init() {
    // Security.addProvider(new BouncyCastleProvider());
    // Cipher ciphersuite;
    //
    // try {
    // ciphersuite = Cipher.getInstance(config.getConfidentiality(), "BC");
    // } catch (NoSuchAlgorithmException e) {
    // ciphersuite = null;
    // e.printStackTrace();
    // } catch (NoSuchPaddingException e) {
    // ciphersuite = null;
    // e.printStackTrace();
    // } catch (NoSuchProviderException e) {
    // ciphersuite = null;
    // e.printStackTrace();
    // }
    //
    // this.cipher = ciphersuite;
    //
    // this.key = new SecretKeySpec(config.getSymmetricKeyBytes(),
    // config.getConfidentiality().split("/")[0]);
    //
    // if (config.getIV() != null) {
    // if (config.usesGCM()) {
    // this.ivSpec = null;
    // } else {
    // this.ivSpec = new IvParameterSpec(config.getIVBytes());
    // }
    // } else {
    // this.ivSpec = null;
    // }
    //
    // MessageDigest hash = null;
    // try {
    // if (config.usesMAC()) {
    // if (config.usesGMAC()) {
    // if (config.getMAC().toUpperCase().contains("AES")) {
    // this.GMAC =
    // new GMac(new GCMBlockCipher(new AESEngine()));
    // } else if (config.getMAC().toUpperCase().contains("RC6")) {
    // this.GMAC =
    // new GMac(new GCMBlockCipher(new RC6Engine()));
    // } else {
    // throw new IllegalArgumentException("Unsupported GMAC");
    // }
    // } else {
    // SecretKey macKey = new SecretKeySpec(
    // config.getMACKeyBytes(), config.getMAC());
    //
    // this.MAC = Mac.getInstance(config.getMAC());
    // this.MAC.init(macKey);
    // }
    // } else {
    // hash = MessageDigest.getInstance(config.getHashFunction());
    // }
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    //
    // this.hash = hash;
    // }
    //
    // public byte[] generateHash(byte[] data, short seqNr) {
    // if (config.usesMAC()) {
    // if (config.usesGMAC()) {
    // KeyParameter keyParam =
    // new KeyParameter(config.getSymmetricKeyBytes());
    // ParametersWithIV params =
    // new ParametersWithIV(keyParam, generateIVBytes(seqNr));
    //
    // GMAC.init(params);
    //
    // GMAC.update(data, 0, data.length);
    //
    // byte[] gmac = new byte[GMAC.getMacSize()];
    // GMAC.doFinal(gmac, 0);
    //
    // return gmac;
    // }
    //
    // return MAC.doFinal(data);
    // }
    //
    // return hash.digest(data);
    // }
    //
    // public boolean validateHash(byte[] hash, byte[] otherHash) {
    // return MessageDigest.isEqual(hash, otherHash);
    // }
    //
    // public int getHashLength() {
    // if (config.usesMAC()) {
    // if (config.usesGMAC()) {
    // return GMAC.getMacSize();
    // }
    // return MAC.getMacLength();
    // }
    //
    // return hash.getDigestLength();
    // }
    //
    // private GCMParameterSpec generateGCMSpec(short seqNr) {
    // return new GCMParameterSpec(config.getIVSize() * 8,
    // generateIVBytes(seqNr));
    // }
    //
    // private IvParameterSpec generateIVSpec(short seqNr) {
    // return new IvParameterSpec(generateIVBytes(seqNr));
    // }
    //
    // private byte[] generateIVBytes(short seqNr) {
    //
    // byte[] newIV = new byte[config.getIVSize()];
    // System.arraycopy(config.getIVBytes(), 0, newIV, 0, 4);
    //
    // for (int i = 11; i >= 4; i--) {
    // newIV[i] = (byte)(seqNr & 0xFF);
    // seqNr >>>= 8;
    // }
    //
    // return newIV;
    // }
    //
    // public byte[] encrypt(byte[] data, short seqNr) throws Exception {
    // if (this.ivSpec != null) {
    // if (config.usesChaCha()) {
    // this.ivSpec = generateIVSpec(seqNr);
    // }
    // cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    // } else if (config.usesGCM()) {
    // cipher.init(Cipher.ENCRYPT_MODE, key, generateGCMSpec(seqNr));
    // } else {
    // cipher.init(Cipher.ENCRYPT_MODE, key);
    // }
    //
    // return cipher.doFinal(data);
    // }
    //
    // public byte[] decrypt(byte[] data, short seqNr) throws Exception {
    // if (this.ivSpec != null) {
    // if (config.usesChaCha()) {
    // this.ivSpec = generateIVSpec(seqNr);
    // }
    // cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    // } else if (config.usesGCM()) {
    // cipher.init(Cipher.DECRYPT_MODE, key, generateGCMSpec(seqNr));
    // } else {
    // cipher.init(Cipher.DECRYPT_MODE, key);
    // }
    //
    // return cipher.doFinal(data);
    // }
    //
    // public String summary() { return config.summary(); }
    //
    // @Override
    // public String toString() {
    // return config.toString();
    // }
    //
    // private class CryptoConfig {
    // private String confidentiality; // ALG/MODE/PADDING
    // private String symmetricKey; // in hex
    // private int symmetricKeySize; // in bits
    // private Integer IVSize; // int or NULL
    // private String IV; // hex or NULL
    // private String integrity; // HMAC or H
    // private String hashFunction; // secure hash func or NULL
    // private String MAC; // HMAC or CMAC
    // private String MACKey; // in hex or NULL
    // private Integer MACKeySize; // in bits
    //
    // // default config name
    // private CryptoConfig() { parseCryptoConfigFile("cryptoconfig.txt"); }
    //
    // private CryptoConfig(String filename) {
    // parseCryptoConfigFile(filename);
    // }
    //
    // // professor, can we use a .props file next time? :(
    // private void parseCryptoConfigFile(String filename) {
    // try (BufferedReader reader =
    // new BufferedReader(new FileReader(filename))) {
    // String line;
    // while ((line = reader.readLine()) != null) {
    // final String[] parts = line.split(":", 2);
    // final String key = parts[0].trim();
    // final String value = parts[1].trim();
    //
    // switch (key) {
    // case "CONFIDENTIALITY":
    // this.confidentiality = value;
    // break;
    // case "SYMMETRIC_KEY":
    // this.symmetricKey = value;
    // break;
    // case "SYMMETRIC_KEY_SIZE":
    // this.symmetricKeySize = Integer.parseInt(value);
    // break;
    // case "IV_SIZE":
    // this.IVSize = value.equals("NULL")
    // ? null
    // : Integer.parseInt(value);
    // break;
    // case "IV":
    // this.IV = value.equals("NULL") ? null : value;
    // break;
    // case "INTEGRITY":
    // this.integrity = value;
    // break;
    // case "H":
    // this.hashFunction = value.equals("NULL") ? null : value;
    // break;
    // case "MAC":
    // this.MAC = value;
    // break;
    // case "MACKEY":
    // this.MACKey = value.equals("NULL") ? null : value;
    // break;
    // case "MACKEY_SIZE":
    // this.MACKeySize = value.equals("NULL")
    // ? null
    // : Integer.parseInt(value);
    // break;
    // }
    // }
    // } catch (final IOException e) {
    // throw new RuntimeException("Error reading " + filename, e);
    // }
    // }
    //
    // public boolean usesMAC() {
    // return "HMAC".equals(this.integrity.toUpperCase()) ||
    // "CMAC".equals(this.integrity.toUpperCase());
    // }
    //
    // public boolean usesGMAC() {
    // return this.MAC.toUpperCase().contains("GMAC");
    // }
    //
    // public boolean usesGCM() {
    // return this.confidentiality.toUpperCase().contains("GCM");
    // }
    //
    // public boolean usesChaCha() {
    // return this.confidentiality.toUpperCase().contains("CHACHA");
    // }
    //
    // public String getConfidentiality() { return this.confidentiality; }
    //
    // public String getSymmetricKey() { return this.symmetricKey; }
    //
    // public byte[] getSymmetricKeyBytes() {
    // return Utils.hexToBytes(this.symmetricKey);
    // }
    //
    // public int getSymmetricKeySize() { return this.symmetricKeySize; }
    //
    // public int getIVSize() { return this.IVSize; }
    //
    // public String getIV() { return this.IV; }
    //
    // public byte[] getIVBytes() { return Utils.hexToBytes(this.IV); }
    //
    // public String getIntegrity() { return this.integrity; }
    //
    // public String getHashFunction() { return this.hashFunction; }
    //
    // public String getMAC() { return this.MAC; }
    //
    // public String getMACKey() { return this.MACKey; }
    //
    // public byte[] getMACKeyBytes() { return Utils.hexToBytes(this.MACKey); }
    //
    // public int getMACKeySize() { return this.MACKeySize; }
    //
    // public String summary() {
    // return confidentiality + " | " + integrity + " | " +
    // (usesMAC() ? MAC : hashFunction) + "\n";
    // }
    //
    // @Override
    // public String toString() {
    // return "CryptoConfig [" +
    // "\n CONFIDENTIALITY = " + confidentiality +
    // "\n SYMMETRIC_KEY = " + symmetricKey +
    // "\n SYMMETRIC_KEY_SIZE = " + symmetricKeySize +
    // "\n IV_SIZE = " + IVSize +
    // "\n IV = " + IV +
    // "\n INTEGRITY = " + integrity +
    // "\n H = " + hashFunction +
    // "\n MAC = " + MAC +
    // "\n MACKEY = " + MACKey +
    // "\n MACKEY_SIZE = " + MACKeySize +
    // "\n]";
    // }
    // }
}
