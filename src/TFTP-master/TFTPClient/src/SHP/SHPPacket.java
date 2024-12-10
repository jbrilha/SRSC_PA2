package SHP;

import java.io.InputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;

/**
 * SHPPacket
 */
public class SHPPacket implements Serializable {
    private SHPHeader header;
    private SHPPayload payload;

    public SHPPacket() {
    }

    public SHPPacket(SHPHeader header, SHPPayload payload) {
        this.header = header;
        this.payload = payload;
    }

    // public static SHPPacket fromByteArray(byte[] data) {
    //     SHPHeader header = SHPHeader.fromPacket(data);
    //     SHPPayload payload = SHPPayload.fromPacket(data);
    //
    //     return new SHPPacket(header, payload);
    // }
    //
    // public static SHPPacket fromInputStream(InputStream in) {
    //     try {
    //         byte[] headerBytes = new byte[SHPHeader.HEADER_SIZE];
    //         in.read(headerBytes);
    //         SHPHeader header = SHPHeader.fromBytes(headerBytes);
    //
    //         byte[] payloadBytes = new byte[header.getMsgSize()];
    //         int readBytes = in.read(payloadBytes);
    //         SHPPayload payload = SHPPayload.fromBytes(payloadBytes, readBytes);
    //
    //         return new SHPPacket(header, payload);
    //
    //     } catch (Exception e) {
    //         return null;
    //     }
    // }

    public SHPHeader getHeader() {
        return header;
    }

    public void setHeader(SHPHeader header) {
        this.header = header;
    }

    public SHPPayload getPayload() {
        return payload;
    }

    public void setPayload(SHPPayload payload) {
        this.payload = payload;
    }
    //
    // public byte[] toByteArray() {
    //     return ByteBuffer
    //             .allocate(SHPHeader.HEADER_SIZE + payload.getDataLength())
    //             .put(this.header.toByteArray())
    //             .put(this.payload.getData())
    //             .array();
    // }

    @Override
    public String toString() {
        return "Payload [\n\t" + header + "\n\t" + payload + "\n]";
    }
}
