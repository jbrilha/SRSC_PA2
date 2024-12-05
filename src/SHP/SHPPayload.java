package SHP;

import java.io.BufferedReader;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * SHPPayload
 */
public class SHPPayload implements Serializable {
    private byte[] data;
    private CryptoHandler cryptoHandler;

    private byte[] rawPayload;
    private byte[] processedPayload;

    public SHPPayload() {}

    public static class Type1 extends SHPPayload {
        public byte[] userId;

        public Type1(byte[] data) { this.userId = data; }

        public String getUserId() {
            return new String(userId, 0, userId.length).trim();
        }

        @Override
        public String toString() {
            return "Payload [userId = " + getUserId() + "]";
        }
    }

    public static class Type2 extends SHPPayload {
        public byte[] salt;
        public byte[] counter;
        public byte[] chall;

        public Type2(byte[] salt, byte[] counter, byte[] chall) {
            this.salt = salt;
            this.counter = counter;
            this.chall = chall;
        }

        @Override
        public String toString() {
            return "Payload [salt = " + Utils.bytesToHex(salt) +
                ", counter = " + Utils.bytesToHex(counter) +
                ", chall = " + Utils.bytesToHex(chall) + "]";
        }
    }

    public static class Type3 extends SHPPayload {
        public byte[] PBE;
        public byte[] signature;
        public byte[] ydhClient;
        public byte[] hash;

        public Type3(byte[] pbe) {
            this.PBE = pbe;
            this.signature = new byte[16];
            this.ydhClient = new byte[16];
            this.hash = new byte[16];
        }

        @Override
        public String toString() {
            return "Payload [PBE = " + new String(PBE) +
                ", signature = " + new String(signature) +
                ", ydhClient = " + new String(ydhClient) +
                ", hash = " + new String(hash) + "]";
        }
    }

    public SHPPayload(byte[] data) { this.data = data; }

    public SHPPayload(byte[] payloadData, CryptoHandler cryptoHandler) {
        this.data = payloadData;
        this.cryptoHandler = cryptoHandler;
    }

    public static SHPPayload fromPacket(byte[] data) {
        return new SHPPayload(
            Arrays.copyOfRange(data, SHPHeader.HEADER_SIZE, data.length));
    }

    public static SHPPayload fromBytes(byte[] data, int len) {
        return new SHPPayload(Arrays.copyOf(data, len));
    }

    public void encrypt() {
        try {
            // this.processedPayload =
            // cryptoHandler.encrypt(this.rawPayload, this.seqNr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decryptAndValidate(short expectedSeqNr, short expectedLength)
        throws Exception {

        if (rawPayload.length != expectedLength) {
            throw new Exception("Payload length [" + rawPayload.length +
                                "] different than expected [" +
                                expectedLength + "]");
        }

        // try {
        // this.processedPayload = cryptoHandler.decrypt(this.rawPayload,
        // expectedSeqNr);
        //
        // } catch (Exception e) {
        // throw new Exception("Payload decryption failed: " + e.getMessage());
        // }

        this.unpackContents();
    }

    public byte[] getData() { return this.data; }

    public int getDataLength() { return this.data.length; }

    public byte[] getProcessedPayload() { return processedPayload; }

    private void unpackContents() {
        ByteBuffer packetBuffer = ByteBuffer.wrap(this.processedPayload, 0,
                                                  this.processedPayload.length);

        this.data = new byte[this.processedPayload.length];
        packetBuffer.get(this.data);
    }

    public byte[] packContents() {
        return ByteBuffer.allocate(data.length).put(this.data).array();
    }

    // public byte[] generateHash() {
    // return cryptoHandler.generateHash(
    // ByteBuffer.allocate(SEQNR_SIZE + data.length)
    // .putShort(this.seqNr)
    // .put(this.data)
    // .array(), seqNr);
    // }

    @Override
    public String toString() {
        String dataString = new String(data, 0, data.length);
        return "Payload [data = " + dataString + "]";
    }
}
