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

    public SHPHeader() {
    }

    public SHPHeader(byte versionRelease, byte msgType) {
        this.versionRelease = versionRelease;
        this.msgType = msgType;
    }

    public SHPHeader(byte version, byte release, byte msgType) {
        setVersion(version);
        setRelease(release);
        this.msgType = msgType;
    }

    public SHPHeader(int version, int release, int msgType) {
        setVersion(version);
        setRelease(release);
        this.msgType = (byte) msgType;
    }

    public static SHPHeader fromPacket(byte[] packetData) {
        ByteBuffer headerData = ByteBuffer.wrap(
            Arrays.copyOf(packetData, HEADER_SIZE));

        byte versionRelease = headerData.get();
        byte msgType = headerData.get();

        return new SHPHeader(versionRelease, msgType);
    }

    // assumes the size is already the same as HEADER_SIZE, therefore needs to
    // be handled before; reason for this is because I want to read the header
    // msgType before reading the rest of the packet as above
    public static SHPHeader fromBytes(byte[] bytes) {
        ByteBuffer headerData = ByteBuffer.wrap(bytes);

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

        this.versionRelease = (byte) ((this.versionRelease & 0X0F) | version << 4);
    }

    public void setRelease(int release) {
        if (release < 0 || release > 15) {
            throw new IllegalArgumentException("Not a valid 4bit value :(");
        }

        this.versionRelease = (byte) ((this.versionRelease & 0XF0) | release);
    }

    public void setMsgType(byte msgType) {
        this.msgType = msgType;
    }

    public int getMsgSize() {
        switch (this.msgType) {
            case 1:
                return 320;
            case 2:
                return 48;
            default:
                // TODO fix this
                return 65000;
        }
    }

    public int getVersion() {
        return (this.versionRelease >> 4) & 0x0F;
    }

    public int getRelease() {
        return this.versionRelease & 0x0F;
    }

    public byte getVersionRelease() {
        return this.versionRelease;
    }

    public short getMsgType() {
        return this.msgType;
    }

    public byte[] toByteArray() {
        return ByteBuffer.allocate(HEADER_SIZE)
                .put(this.versionRelease)
                .put(this.msgType)
                .array();
    }

    @Override
    public String toString() {
        return "Header [version = " + getVersion() +
                " | release = " + getRelease() + " | msgType = " + msgType + "]";
    }
}
