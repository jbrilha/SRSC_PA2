package StreamingService.hjStreamServer; // PA1: added package declaration for easier compilation

/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;

import DSTP.DSTPDatagramSocket; // PA1: added import
import SHP.*; // PA2: added import

class hjStreamServer {

	static public void main( String []args ) throws Exception { // PA2: remove argument count checking
        // PA2: just in case this is actually needed but not in the spec....
        int tcp_port = (args.length == 0 || args[0] == null) ? 3333 : Integer.parseInt(args[0]);
        SHPServer sc = new SHPServer(tcp_port); // PA2: init SHP server
        SHPRequest request = sc.handshake(); // PA2: SHP handshake
        String filename =
            "StreamingService/hjStreamServer/movies/" + request.body;

        int size;
        int count = 0;
        long time;
        DataInputStream g = new DataInputStream( new FileInputStream(filename) ); // PA2: use filename from SHP client request
        byte[] buff = new byte[65000];
        DSTPDatagramSocket s = new DSTPDatagramSocket(request.config); // PA1: changed socket class | PA2: use cryptoconfig from SHP
        InetSocketAddress addr = new InetSocketAddress(sc.sock.getInetAddress().getHostAddress(),
                                        request.udp_port); // PA2: use new host and port from SHP
        DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
        long t0 = System.nanoTime(); // tempo de referencia
        long q0 = 0;

        while ( g.available() > 0 ) {
            size = g.readShort();
            time = g.readLong();
            if ( count == 0 ) q0 = time; // tempo de referencia no stream
            count += 1;
            g.readFully(buff, 0, size );
            p.setData(buff, 0, size );
            p.setSocketAddress( addr );
            long t = System.nanoTime();
            Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
            s.send( p );
            //System.out.print( "." );
        }

        System.out.println("\nEND ! packets with frames sent: "+count);
	}

}
