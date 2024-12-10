package SHP;

import java.io.Serializable;
import java.nio.ByteBuffer;

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
                // limited to something big because object sizes can vary
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
