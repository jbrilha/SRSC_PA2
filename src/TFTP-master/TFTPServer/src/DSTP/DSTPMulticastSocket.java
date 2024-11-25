package DSTP;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.util.Arrays;

/**
 * DSTPMulticastSocket
 */
public class DSTPMulticastSocket extends MulticastSocket {

    private final CryptoHandler cryptoHandler;
    private short sentSeqNr = 0;
    private short recSeqNr = 0;

    public DSTPMulticastSocket() throws IOException {
        this.cryptoHandler = new CryptoHandler("cryptoconfig.txt");

        System.out.println("\nUsing DSTPSocket secured with: " +
                           cryptoHandler.summary());
    }

    public DSTPMulticastSocket(int port) throws IOException {
        super(port);

        this.cryptoHandler = new CryptoHandler("cryptoconfig.txt");

        System.out.println("\nUsing DSTPSocket secured with: " +
                           cryptoHandler.summary());
    }

    public void send(DatagramPacket packet) throws IOException {
        byte[] packetData = packet.getData();
        int packetLength = packet.getLength();

        byte[] payloadData = Arrays.copyOf(packetData, packetLength);

        DSTPPayload payload =
            new DSTPPayload(this.sentSeqNr++, payloadData, cryptoHandler);
        payload.encrypt();
        byte[] processedPayload = payload.getProcessedPayload();

        DSTPHeader header = DSTPHeader.generateFromPayload(processedPayload);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(header.toByteArray());
        baos.write(processedPayload);
        byte[] DSTPPacket = baos.toByteArray();

        // can't use arraycopy here because of length issues when sending
        packet.setData(DSTPPacket, 0, DSTPPacket.length);

        super.send(packet);
    }

    public void receive(DatagramPacket packet) throws IOException {
        super.receive(packet);

        byte[] packetData = packet.getData();
        int packetLength = packet.getLength();

        DSTPHeader header = DSTPHeader.getFromPacket(packetData);

        byte[] payloadData = Arrays.copyOfRange(
            packetData, DSTPHeader.HEADER_SIZE, packetLength);

        DSTPPayload payload =
            DSTPPayload.fromPacket(payloadData, cryptoHandler);

        try {
            payload.decryptAndValidate(this.recSeqNr, header.getPayloadLength());

            this.recSeqNr++;

            byte[] processedPayload = payload.getData();

            System.arraycopy(processedPayload, 0, packetData, 0,
                             processedPayload.length);

            // setData breaks the packet somehow but arraycopy is more
            // performant anyway so might as well use it instead
            // packet.setData(processedPayload);
            packet.setLength(processedPayload.length);
        } catch (Exception e) {
            packet.setData(new byte[0]);
            packet.setLength(0);

            System.out.println("Dropped packet | " + e.getMessage());
        }
    }

    public void setSentSeqNr(short seqNr) {
        this.sentSeqNr = seqNr;
    }

    public void setRecSeqNr(short seqNr) {
        this.recSeqNr = seqNr;
    }
}
