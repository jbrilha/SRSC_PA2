package SHP;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CryptoHandler
 */
public class CryptoHandler {
    private final static String HMAC = "HMAC-SHA512";
    private final static String AES = "AES";

    private MessageDigest hash;
    private Mac mac;
    private Signature signature;
    private Cipher pwCipher;
    private Cipher envCipher;
    private Cipher aesCipher;
    private SecretKeyFactory secKeyFactory;
    private KeyFactory ECKeyFactory;
    private KeyFactory DHKeyFactory;
    private KeyAgreement keyAgreement;
    private DHParameterSpec dhSpec;
    private KeyPairGenerator keyPairGenerator;
    private PrivateKey dhPrivKey;

    private static final BigInteger G2048 = new BigInteger(
            "29921856600312726725233783990862245500844977318481436463708787158053"
                    + "77467115448036145134085699794575169953367800738033395373714534478012"
                    + "38997334994761939046735532050792301435481780477259632834560815824829"
                    + "87865944507925876902318116864687612800046794048720512923467436091935"
                    + "51447149573305643559835039726944776944130993169353084317089130229776"
                    + "92663920407983317099464477375376556374741932689342986904165987179677"
                    + "88220898197447788494104043737106979614932136237837549595753633444959"
                    + "12883417634508652152797989038625331065651788508650985818751822124731"
                    + "51882329639419557750694932382824755364359901017619088709955837582398"
                    + "46390");
    private static final BigInteger P2048 = new BigInteger(
            "31264549318166531867496794807473238141433566771809815847049814274020"
                    + "05163271727770273721302685518597878750943052261821179926802000714112"
                    + "31421485890780606522846665768330062360819010369111884370353470845933"
                    + "92127470094806637074883324841802919100101385270091934681784803438875"
                    + "62123322167195720477951820617476155964519726598021984585347233205156"
                    + "44583288928898374740261143293397325572959009034187560158849399849537"
                    + "85268183285621880561011390630694514604422793454738005834016173550272"
                    + "09042859026074252892315501775316088371091609217985095505147483138286"
                    + "55932825290965877372882317184132366821847106726645935649138663776244"
                    + "00503");

    public CryptoHandler() {
        Security.addProvider(new BouncyCastleProvider());

        try {
            this.ECKeyFactory = KeyFactory.getInstance("EC", "BC");
            this.DHKeyFactory = KeyFactory.getInstance("DH", "BC");
            this.hash = MessageDigest.getInstance("SHA256", "BC");
            this.mac = Mac.getInstance(HMAC, "BC");
            this.signature = Signature.getInstance("SHA256withECDSA", "BC");
            this.pwCipher = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
            this.envCipher = Cipher.getInstance("ECIES", "BC");
            this.aesCipher = Cipher.getInstance(AES, "BC");
            this.secKeyFactory = SecretKeyFactory.getInstance(
                    "PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
            this.keyAgreement = KeyAgreement.getInstance("DH", "BC");
            this.dhSpec = new DHParameterSpec(G2048, P2048);
            this.keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
            this.keyPairGenerator.initialize(dhSpec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    // PublicKey parsing
    public PublicKey parseDHPublicKeyBytes(byte[] bytes)
            throws InvalidKeySpecException {
        return parsePublicKeyBytes(DHKeyFactory, bytes);
    }

    public PublicKey parseECPublicKeyHex(String hex)
            throws InvalidKeySpecException {

        byte[] bytes = Utils.hexToBytes(hex);
        return parsePublicKeyBytes(ECKeyFactory, bytes);
    }

    public PublicKey parsePublicKeyBytes(KeyFactory keyFactory, byte[] bytes)
            throws InvalidKeySpecException {

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        return keyFactory.generatePublic(keySpec);
    }

    // PrivateKey parsing
    public PrivateKey parseECPrivateKeyHex(String hex)
            throws InvalidKeySpecException {

        byte[] bytes = Utils.hexToBytes(hex);
        return parsePrivateKeyBytes(ECKeyFactory, bytes);
    }

    public PrivateKey parseDHPrivateKeyBytes(byte[] bytes)
            throws InvalidKeySpecException {

        return parsePrivateKeyBytes(DHKeyFactory, bytes);
    }

    public PrivateKey parsePrivateKeyBytes(KeyFactory keyFactory, byte[] bytes)
            throws InvalidKeySpecException {

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        return keyFactory.generatePrivate(keySpec);
    }

    // Encryption
    public byte[] performSymetricEncryption(byte[] data, byte[] secret)
            throws Exception {
        SecretKeySpec key = new SecretKeySpec(secret, AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, key);
        return aesCipher.doFinal(data);
    }

    public byte[] performAssymetricEncryption(byte[] data, PublicKey pubKey)
            throws Exception {
        envCipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return envCipher.doFinal(data);
    }

    public byte[] performPasswordEncryption(byte[] data, byte[] password,
            byte[] salt, byte[] counter)
            throws Exception {
        String pwHex = Utils.bytesToHex(password);
        PBEKeySpec pwSpec = new PBEKeySpec(pwHex.toCharArray());
        Key sKey = secKeyFactory.generateSecret(pwSpec);

        String counterStr = Utils.bytesToHex(counter);
        BigInteger counterBigInt = new BigInteger(counterStr, 16);
        int counterInt = Math.max(counterBigInt.intValue() & 0xFFFF, 8192);
        System.out.println("cint: " + counterInt);

        // TODO FIX COUNTER
        pwCipher.init(Cipher.ENCRYPT_MODE, sKey,
                new PBEParameterSpec(salt, counterInt));

        return pwCipher.doFinal(data);
    }

    // Decryption
    public byte[] performSymetricDecryption(byte[] data, byte[] secret)
            throws Exception {
        SecretKeySpec key = new SecretKeySpec(secret, AES);
        aesCipher.init(Cipher.DECRYPT_MODE, key);
        return aesCipher.doFinal(data);
    }

    public byte[] performAssymetricDecryption(byte[] data, PrivateKey key)
            throws Exception {
        envCipher.init(Cipher.DECRYPT_MODE, key);
        return envCipher.doFinal(data);
    }

    public byte[] performPasswordDecryption(byte[] data, byte[] password,
            byte[] salt, byte[] counter)
            throws Exception {
        String pwHex = Utils.bytesToHex(password);
        PBEKeySpec pwSpec = new PBEKeySpec(pwHex.toCharArray());
        Key sKey = secKeyFactory.generateSecret(pwSpec);

        String counterStr = Utils.bytesToHex(counter);
        BigInteger counterBigInt = new BigInteger(counterStr, 16);
        int counterInt = Math.max(counterBigInt.intValue() & 0xFFFF, 8192);

        // TODO FIX COUNTER
        pwCipher.init(Cipher.DECRYPT_MODE, sKey,
                new PBEParameterSpec(salt, counterInt));

        return pwCipher.doFinal(data);
    }

    // DH key gen
    public byte[] generateDHPubKey() throws Exception {
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.dhPrivKey = keyPair.getPrivate();
        return keyPair.getPublic().getEncoded();
    }

    public byte[] generateSharedSecret(byte[] dhKey) throws Exception {
        PublicKey dhPubKey = parseDHPublicKeyBytes(dhKey);
        keyAgreement.init(this.dhPrivKey);
        keyAgreement.doPhase(dhPubKey, true);
        return keyAgreement.generateSecret();
    }

    // Other sec property generators
    public byte[] generateMAC(byte[] key, byte[]... data) throws Exception {
        Key sKey = new SecretKeySpec(key, HMAC);
        mac.init(sKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] arr : data) {
            baos.write(arr);
        }
        mac.update(baos.toByteArray());

        return mac.doFinal();
    }

    public byte[] generateSignature(PrivateKey key, byte[] data)
            throws Exception {
        signature.initSign(key, new SecureRandom());
        signature.update(data);
        return signature.sign();
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

    public static byte[] generateChallenge(byte[] nonce) {
        BigInteger nonceInt = new BigInteger(1, nonce);
        BigInteger chall = nonceInt.add(BigInteger.ONE);

        return chall.toByteArray();
    }

    public static boolean validateChallenge(byte[] chall, byte[] nonce) {
        return MessageDigest.isEqual(chall, generateChallenge(nonce));
    }

    public void updateCiphersuite(CryptoConfig cc, byte[] secret)
            throws Exception {
        int ivSize = cc.getIVSize();
        if (ivSize > 0) {
            byte[] ivInfo = "IV".getBytes();
            var IV = Utils.bytesToHex(deriveKeyFromSecret(ivSize, ivInfo, secret));
            cc.setIV(IV);
        }

        int macKeySize = cc.getMACKeySize() / 8;
        if (macKeySize > 0) {
            byte[] macKeyInfo = "MAC_KEY".getBytes();
            var macKey = Utils.bytesToHex(
                    deriveKeyFromSecret(macKeySize, macKeyInfo, secret));
            cc.setMACKey(macKey);
        }

        int symKeySize = cc.getSymmetricKeySize() / 8;
        byte[] symKeyInfo = "SYMMETRIC_KEY".getBytes();
        var symKey = Utils.bytesToHex(
                deriveKeyFromSecret(symKeySize, symKeyInfo, secret));
        cc.setSymmetricKey(symKey);
    }

    // HKDF from a couple of places
    // https://www.javatips.net/api/keywhiz-master/hkdf/src/main/java/keywhiz/hkdf/Hkdf.java
    // https://github.com/signalapp/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/kdf/HKDF.java
    // https://github.com/patrickfav/hkdf/blob/main/src/main/java/at/favre/lib/hkdf/HKDF.java
    // https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/sun/security/ssl/HKDF.java
    public byte[] deriveKeyFromSecret(int length, byte[] info, byte[] secret)
            throws Exception {
        mac.init(new SecretKeySpec(secret, HMAC));
        byte[] pseudoRand = mac.doFinal(new byte[32]);
        mac.init(new SecretKeySpec(pseudoRand, HMAC));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] prev = new byte[0];
        byte counter = 1;

        while (output.size() < length) {
            mac.reset();
            mac.update(prev);
            mac.update(info);
            mac.update(counter++);
            prev = mac.doFinal();
            output.write(prev);
        }

        return Arrays.copyOf(output.toByteArray(), length);
    }

    // Other sec property validators
    public boolean validateMAC(byte[] key, byte[] expected, byte[]... data)
            throws Exception {
        Key sKey = new SecretKeySpec(key, HMAC);
        mac.init(sKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] arr : data) {
            baos.write(arr);
        }
        mac.update(baos.toByteArray());

        return MessageDigest.isEqual(expected, mac.doFinal());
    }

    public boolean validateSignature(PublicKey key, byte[] sig, byte[] expected)
            throws Exception {

        signature.initVerify(key);
        signature.update(expected);
        return signature.verify(sig);
    }

    public boolean validatePassword(byte[] received, byte[] expected) {
        return MessageDigest.isEqual(received, expected);
    }
}
