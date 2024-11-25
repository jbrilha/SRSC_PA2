import java.net.*;
import java.io.*;
import java.util.*;

import DSTP.DSTPDatagramSocket; // PA1: added import line

public class TFTPServer {

	public static void main(String argv[]) {
		try {
			//use port 6973
			DSTPDatagramSocket sock = new DSTPDatagramSocket(6973); // PA1: changed socket class
			System.out.println("Server Ready.  Port:  " + sock.getLocalPort());

			// Listen for requests
			while (true) {
				TFTPpacket in = TFTPpacket.receive(sock);
                sock.setRecSeqNr((short)0); // PA1: reset recSeqNr to allow for fresh connections on the main socket
				// receive read request
				if (in instanceof TFTPread) {
					System.out.println("Read Request from " + in.getAddress());
					TFTPserverRRQ r = new TFTPserverRRQ((TFTPread) in);
				}
				// receive write request
				else if (in instanceof TFTPwrite) {
					System.out.println("Write Request from " + in.getAddress());
					TFTPserverWRQ w = new TFTPserverWRQ((TFTPwrite) in);
				}
			}
		} catch (SocketException e) {
			System.out.println("Server terminated(SocketException) " + e.getMessage());
		} catch (TftpException e) {
			System.out.println("Server terminated(TftpException)" + e.getMessage());
		} catch (IOException e) {
			System.out.println("Server terminated(IOException)" + e.getMessage());
		}
	}
}
