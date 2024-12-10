package StreamingService.hjUDPproxy; // PA1: added package declaration for easier compilation

/* hjUDPproxy, for use in 2024
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import DSTP.DSTPDatagramSocket; // PA1: added import
import SHP.*; // PA2: added import

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        if (args.length != 7) { // PA2: moved help to bottom of file
            showHelp();
            System.exit(0);
        }
	
        // PA2: parsing new args, do I count these lines in the form?
        String username = args[0];
        String password = args[1];
        String hostAddr = args[2];
        int tcp_port = Integer.parseInt(args[3]);
        String movie = args[4].contains(".dat") ? args[4] : args[4] + ".dat";

        int udp_port = Integer.parseInt(args[5]);
        int playerPort = Integer.parseInt(args[6]);

        SHPClient sc = new SHPClient(hostAddr, tcp_port);
        CryptoConfig cc = sc.handshake(username, password, movie, udp_port); // PA2: SHP handshake

        SocketAddress inSocketAddress = new InetSocketAddress(hostAddr, udp_port); // PA2: socket creation with new args
        SocketAddress outSocketAddress = new InetSocketAddress(hostAddr, playerPort); // PA2: socket creation with new args

        // Manage this according to your required setup, namely
	// if you want to use unicast or multicast channels

        // If listen a remote unicast server try the remote config
        // uncomment the following line
	
	 DSTPDatagramSocket inSocket = new DSTPDatagramSocket(inSocketAddress, cc); // PA1: changed socket class | PA2: added CryptoConfig as param

	// If listen a remote multicast server using IP Multicasting
        // addressing (remember IP Multicast Range) and port 
	// uncomment the following two lines

	//	MulticastSocket ms = new MulticastSocket(9999);
	//        ms.joinGroup(InetAddress.getByName("239.9.9.9"));

	int countframes=0;
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
        while (true) {

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
	    // If listen a remote unicast server
	    // uncomment the following line

	    inSocket.receive(inPacket);  // if remote is unicast

	    // If listen a remote multcast server
	    // uncomment the following line

            //ms.receive(inPacket);          // if remote is multicast

	    // Just for debug... 
            //countframes++;
            //System.out.println(":"+countframes);           // debug	    
            //System.out.print(":");           // debug
            // for (SocketAddress outSocketAddress : outSocketAddressSet) 
		// {
                // PA2: use single socket
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
            // }
        }
    }

    private static void showHelp() {
        System.out.println(
                "Usage: hjUDPproxy <username> <password> <host_addr> "
                        + "<tcp_port> <movie> <udp_port> <player_port>\n");

        System.out.println("<username>: username of the client making request");
        System.out.println("<password>: password of the client");
        System.out.println("<host_addr>: address where communications will occur");
        System.out.println("<tcp_port>: port that server is listening on");
        System.out.println("<movie>: requested movie");
        System.out.println("<udp_port>: port where movie will be received from (on host_addr)");
        System.out.println("<player_port>: port where movie will be streamed to (on host_addr)");

        System.out.println("Ex: hjUDPproxy user1 password1 127.0.0.1 3333 cars 5555 9999");
        System.out.println("Ex: hjUDPproxy user2 password2 172.50.0.2 3333 monsters.dat 5555 9999");
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
