package SHP;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * SHPHeader
 */
public class SHPHeader implements Serializable {
    public final static int HEADER_SIZE = 2; // 4b + 4b + 8b = 16b = 2B

    private byte versionRelease;
    private byte msgType;

    public SHPHeader() {}

    public SHPHeader(byte versionRelease, byte msgType) {
        this.versionRelease = versionRelease;
        this.msgType = msgType;
    }

    public SHPHeader(byte version, byte release, byte msgType) {
        setVersion(version);
        setRelease(release);
        this.msgType = msgType;
    }

    public static SHPHeader generateFromPayload(byte[] payload) {
        byte versionRelease = 0x22;
        byte msgType = 'c';

        return new SHPHeader(versionRelease, msgType);
    }

    public static SHPHeader getFromPacket(byte[] packetData) {
        ByteBuffer headerData =
            ByteBuffer.wrap(Arrays.copyOf(packetData, HEADER_SIZE));

        byte versionRelease = headerData.get();
        byte msgType = headerData.get();

        return new SHPHeader(versionRelease, msgType);
    }

    public void setRelease(byte versionRelease) {
        this.versionRelease = versionRelease;
    }

    public void setVersion(int version) {
        if (version < 0 || version > 15) {
            throw new IllegalArgumentException("Not a valid 4bit value :(");
        }

        this.versionRelease =
            (byte)((this.versionRelease & 0X0F) | version << 4);
    }

    public void setRelease(int release) {
        if (release < 0 || release > 15) {
            throw new IllegalArgumentException("Not a valid 4bit value :(");
        }

        this.versionRelease = (byte)((this.versionRelease & 0XF0) | release);
    }

    public void setMsgType(byte msgType) { this.msgType = msgType; }

    public int getVersion() { return (this.versionRelease >> 4) & 0x0F; }

    public int getRelease() { return this.versionRelease & 0x0F; }

    public byte getVersionRelease() { return this.versionRelease; }

    public short getMsgType() { return this.msgType; }

    public byte[] toByteArray() {
        return ByteBuffer
            .allocate(HEADER_SIZE)
            .put(this.versionRelease)
            .put(this.msgType)
            .array();
    }

    @Override
    public String toString() {

        return "Header [version = " + getVersion() +
            " | release = " + getRelease() +
            " | msgType = " + msgType + "]";
    }
}
