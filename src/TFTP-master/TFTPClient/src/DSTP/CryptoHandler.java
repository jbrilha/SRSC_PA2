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
import SHP.CryptoConfig;

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
        this.config = new CryptoConfig("ciphersuite.conf");
        init();
    }

    public CryptoHandler(CryptoConfig cc) {
        this.config = cc;
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
            return config.getMACKeySize() / 8;
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
}

