package StreamingService.hjStreamServer; // PA1: added package declaration for easier compilation

/*
 * hjStreamServer.java
 * Streaming server: emitter of video streams (movies)
 * Can send in unicast or multicast IP for client listeners
 * that can play in real time the transmitted movies
 */

import DSTP.DSTPDatagramSocket; // PA1: added import
import SHP.*;
import java.io.*;
import java.net.*;

class hjStreamServer {

    static public void main(String[] args) throws Exception {
        SHPServer sc = new SHPServer();
        try {
            SHPRequest request = sc.handshake();
            String filename =
                "StreamingService/hjStreamServer/movies/" + request.body;

            String host = sc.sock.getInetAddress().getHostAddress();
            int port = request.udp_port;
            System.out.println(request);


            DataInputStream g =
                new DataInputStream(new FileInputStream(filename));
            int size;
            int count = 0;
            long time;
            byte[] buff = new byte[65000];
            DSTPDatagramSocket s =
                new DSTPDatagramSocket(request.config); // PA1: changed socket class
            InetSocketAddress addr = new InetSocketAddress(host, port);
            DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
            long t0 = System.nanoTime(); // tempo de referencia
            long q0 = 0;

            while (g.available() > 0) {
                size = g.readShort();
                time = g.readLong();
                if (count == 0)
                    q0 = time; // tempo de referencia no stream
                count += 1;
                g.readFully(buff, 0, size);
                p.setData(buff, 0, size);
                p.setSocketAddress(addr);
                long t = System.nanoTime();
                Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));
                s.send(p);
                // System.out.print( "." );
            }
            s.close();
            g.close();

            System.out.println("\nEND ! packets with frames sent: " + count);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }
}
