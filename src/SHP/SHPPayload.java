package SHP;

import java.io.BufferedReader;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * SHPPayload
 */
public class SHPPayload {
    private byte[] data;
    private CryptoHandler cryptoHandler;

    private byte[] rawPayload;
    private byte[] processedPayload;

    public SHPPayload() {
    }

    public SHPPayload(byte[] data) {
        this.data = data;
    }

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

        try {
            this.processedPayload = cryptoHandler.decrypt(this.rawPayload, expectedSeqNr);

        } catch (Exception e) {
            throw new Exception("Payload decryption failed: " + e.getMessage());
        }

        this.unpackContents();
    }

    public byte[] getData() {
        return this.data;
    }

    public int getDataLength() {
        return this.data.length;
    }

    public byte[] getProcessedPayload() {
        return processedPayload;
    }

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
