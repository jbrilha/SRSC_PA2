package DSTP;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * DSTPHeader
 */
public class DSTPHeader {
    public final static int HEADER_SIZE = 5; // 16b + 8b + 16b = 40b = 5B

    private short version;
    private byte release;
    private short payloadLength;

    public DSTPHeader() {}

    public DSTPHeader(short version, byte release, short payloadLength) {
        this.version = version;
        this.release = release;
        this.payloadLength = payloadLength;
    }

    public static DSTPHeader generateFromPayload(byte[] payload) {
        short version = 0x11;
        byte release = 0x22;
        short payloadLength = (short)payload.length;

        return new DSTPHeader(version, release, payloadLength);
    }

    public static DSTPHeader getFromPacket(byte[] packetData) {
        ByteBuffer headerData =
            ByteBuffer.wrap(Arrays.copyOf(packetData, HEADER_SIZE));

        short version = headerData.getShort();
        byte release = headerData.get();
        short payloadLength = headerData.getShort();

        return new DSTPHeader(version, release, payloadLength);
    }

    public void setVersion(short version) { this.version = version; }

    public void setRelease(byte release) { this.release = release; }

    public void setPayloadLength(short payloadLength) {
        this.payloadLength = payloadLength;
    }

    public short getVersion() { return this.version; }

    public byte getRelease() { return this.release; }

    public short getPayloadLength() { return this.payloadLength; }

    public byte[] toByteArray() {
        return ByteBuffer.allocate(HEADER_SIZE)
            .putShort(this.version)
            .put(this.release)
            .putShort(this.payloadLength)
            .array();
    }

    @Override
    public String toString() {
        return "Header [version = " + version + " | release = " + release +
            " | payloadLength = " + payloadLength + "]";
    }
}
