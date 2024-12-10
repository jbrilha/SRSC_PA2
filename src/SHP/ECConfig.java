package SHP;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ECConfig {
    String curve;
    PublicKey publicKey;
    PrivateKey privateKey;

    public ECConfig(String curve, PrivateKey privKey, PublicKey pubKey) {
        this.curve = curve;
        this.privateKey = privKey;
        this.publicKey = pubKey;
    }

    public static ECConfig parseConfigFile(String secFile,
                                              CryptoHandler cryptoHandler) {
        try (BufferedReader reader =
                 new BufferedReader(new FileReader(secFile))) {
            String curve = reader.readLine().split(":")[1].trim();

            String privKeyHex = reader.readLine().split(":")[1].trim();
            PrivateKey privKey = cryptoHandler.parseECPrivateKeyHex(privKeyHex);

            String pubKeyHex = reader.readLine().split(":")[1].trim();
            PublicKey pubKey = cryptoHandler.parseECPublicKeyHex(pubKeyHex);

            return new ECConfig(curve, privKey, pubKey);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getCurve() { return curve; }

    public PublicKey getPublicKey() { return publicKey; }

    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String toString() {
        String privateKey = Utils.bytesToHex(this.privateKey.getEncoded());
        String publicKey = Utils.bytesToHex(this.publicKey.getEncoded());

        return "ECConfig [curve = " + this.curve +
            " | privateKey = " + privateKey + " | publicKey = " + publicKey +
            "]";
    }
}
