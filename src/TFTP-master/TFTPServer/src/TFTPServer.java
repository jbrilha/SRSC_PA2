import java.net.*;
import java.io.*;
import java.util.*;

import DSTP.DSTPDatagramSocket; // PA1: added import line
import SHP.*; // PA2: added import

public class TFTPServer {

	public static void main(String argv[]) {
		try {
            int tcp_port = argv[0] == null ? 3333 : Integer.parseInt(argv[0]); // PA2: default 3333 or parse arg
            while(true) { // PA2: move while here to handshake w every new client
                            // means the ciphersuite can be different for each client, which is neat :)
                SHPServer sc = new SHPServer(tcp_port);
                SHPRequest request = sc.handshake(); // PA2: SHP handshake
                CryptoConfig cc = request.config;

                //use port 6973 // PA2: the client sends this port
                DSTPDatagramSocket sock = new DSTPDatagramSocket(request.udp_port, cc); // PA1: changed socket class
                System.out.println("Server Ready.  Port:  " + sock.getLocalPort());

                // Listen for requests
				TFTPpacket in = TFTPpacket.receive(sock);
                sock.setRecSeqNr((short)0); // PA1: reset recSeqNr to allow for fresh connections on the main socket
				// receive read request
				if (in instanceof TFTPread) {
					System.out.println("Read Request from " + in.getAddress());
					TFTPserverRRQ r = new TFTPserverRRQ((TFTPread) in, cc);
				}
				// receive write request
				else if (in instanceof TFTPwrite) {
					System.out.println("Write Request from " + in.getAddress());
					TFTPserverWRQ w = new TFTPserverWRQ((TFTPwrite) in, cc);
				}
            }
		} catch (SocketException e) {
			System.out.println("Server terminated(SocketException) " + e.getMessage());
		} catch (TftpException e) {
			System.out.println("Server terminated(TftpException)" + e.getMessage());
		} catch (IOException e) {
			System.out.println("Server terminated(IOException)" + e.getMessage());
        } catch (Exception e) { // PA2: catch exception from SHP handshake
            e.printStackTrace();
        }
	}
}
