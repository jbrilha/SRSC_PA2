package DSTP;

import java.nio.ByteBuffer;

/**
 * DSTPPayload
 */
public class DSTPPayload {
    private static final int SEQNR_SIZE = 2;

    private short seqNr;
    private byte[] data;
    private CryptoHandler cryptoHandler;
    private byte[] hash;

    private byte[] rawPayload;
    private byte[] processedPayload;

    public DSTPPayload() {}

    public DSTPPayload(short seqNr, byte[] payloadData,
                       CryptoHandler cryptoHandler) {
        this.seqNr = seqNr;
        this.data = payloadData;
        this.cryptoHandler = cryptoHandler;

        this.hash = generateHash();

        this.rawPayload = packContents();
    }

    public DSTPPayload(byte[] payloadData, CryptoHandler cryptoHandler) {

        this.cryptoHandler = cryptoHandler;
        this.rawPayload = payloadData;
    }

    public static DSTPPayload fromPacket(byte[] packetData,
                                         CryptoHandler cryptoHandler) {

        return new DSTPPayload(packetData, cryptoHandler);
    }

    public void encrypt() {
        try {
            this.processedPayload =
                cryptoHandler.encrypt(this.rawPayload, this.seqNr);
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
            this.processedPayload =
                cryptoHandler.decrypt(this.rawPayload, expectedSeqNr);

        } catch (Exception e) {
            throw new Exception("Payload decryption failed: " + e.getMessage());
        }

        this.unpackContents();

        if (getSeqNr() != expectedSeqNr) {
            throw new Exception("Payload sequence number [" + getSeqNr() +
                                "] different than expected [" +
                                expectedSeqNr + "]");
        }

        if (!validateHash()) {
            throw new Exception("Tampering detected: Invalid Hash or [C/H]MAC");
        }
    }

    private boolean validateHash() {
        byte[] generatedHash = generateHash();
        // System.out.println(Utils.bytesToHex(generatedHash));
        return cryptoHandler.validateHash(this.hash, generatedHash);
    }

    public void setSeqNr(short seqNr) { this.seqNr = seqNr; }

    public void setHash(byte[] hash) { this.hash = hash; }

    public short getSeqNr() { return this.seqNr; }

    public byte[] getData() { return this.data; }

    public byte[] getHash() { return this.hash; }

    public byte[] getProcessedPayload() { return processedPayload; }

    private void unpackContents() {
        ByteBuffer packetBuffer = ByteBuffer.wrap(this.processedPayload, 0,
                                                  this.processedPayload.length);

        this.seqNr = packetBuffer.getShort();

        this.data = new byte[this.processedPayload.length - SEQNR_SIZE -
                             cryptoHandler.getHashLength()];
        packetBuffer.get(this.data);

        this.hash = new byte[cryptoHandler.getHashLength()];
        packetBuffer.get(this.hash);
    }

    public byte[] packContents() {
        return ByteBuffer.allocate(SEQNR_SIZE + data.length + hash.length)
            .putShort(this.seqNr)
            .put(this.data)
            .put(this.hash)
            .array();
    }

    public byte[] generateHash() {
        return cryptoHandler.generateHash(
            ByteBuffer.allocate(SEQNR_SIZE + data.length)
                .putShort(this.seqNr)
                .put(this.data)
                .array(), seqNr);
    }

    @Override
    public String toString() {
        return "Payload [seqNr = " + seqNr + " | data = " + data +
            " | hash = " + hash + "]";
    }
}
