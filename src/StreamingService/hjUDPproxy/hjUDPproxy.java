package StreamingService.hjUDPproxy; // PA1: added package declaration for easier compilation

/* hjUDPproxy, for use in 2024
 */

import DSTP.DSTPDatagramSocket; // PA1: added import
import SHP.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        if (args.length != 7) {
            showHelp();
            System.exit(0);
        }

        String username = args[0];
        String password = args[1];
        String hostAddr = args[2];
        int TCPPort = Integer.parseInt(args[3]);
        String movie = args[4].contains(".dat")
                ? args[4]
                : args[4] + ".dat";

        String serverEndpoint = null;
        int serverPort = 0;
        if(args[5].contains(":")) {
            serverEndpoint = args[5];
            serverPort = Integer.parseInt(args[5].split(":")[1]);
        } else {
            serverPort = Integer.parseInt(args[5]);
        }

        String playerEndpoint = null;
        int playerPort = 0;
        if(args[6].contains(":")) {
            playerEndpoint = args[6];
            playerPort = Integer.parseInt(args[6].split(":")[1]);
        } else {
            playerPort = Integer.parseInt(args[6]);
        }

        // for(int i = 0; i < args.length; i++) {
        //     System.out.println("arg[" + i + "]: " + args[i]);
        // }

        SHPClient sc = new SHPClient(hostAddr, TCPPort);
        System.out.println("what?");
        sc.sendRequest(username, password, movie, serverPort);
        sc.destroy();

        SocketAddress inSocketAddress = serverEndpoint == null
                ? new InetSocketAddress(hostAddr, serverPort)
                : parseSocketAddress(serverEndpoint);
        SocketAddress outSocketAddress = playerEndpoint == null
                ? new InetSocketAddress(hostAddr, playerPort)
                : parseSocketAddress(playerEndpoint);

        // Set<SocketAddress> outSocketAddressSet =
        //     Arrays.stream(destinations.split(","))
        //         .map(s -> parseSocketAddress(s))
        //         .collect(Collectors.toSet());

        // Manage this according to your required setup, namely
        // if you want to use unicast or multicast channels

        // If listen a remote unicast server try the remote config
        // uncomment the following line

        DSTPDatagramSocket inSocket = new DSTPDatagramSocket(
            inSocketAddress); // PA1: changed socket class

        // If listen a remote multicast server using IP Multicasting
        // addressing (remember IP Multicast Range) and port
        // uncomment the following two lines

        // MulticastSocket ms = new MulticastSocket(9999);
        // ms.joinGroup(InetAddress.getByName("239.9.9.9"));

        int countframes = 0;
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
        while (true) {

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            // If listen a remote unicast server
            // uncomment the following line

            inSocket.receive(inPacket); // if remote is unicast

            // If listen a remote multcast server
            // uncomment the following line

            // ms.receive(inPacket); // if remote is multicast

            // Just for debug...
            // countframes++;
            // System.out.println(":"+countframes); // debug
            // System.out.print(":"); // debug
            // for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(),
                                                  outSocketAddress));
            // }
        }
        // inSocket.close();
        // outSocket.close();
    }

    private static void showHelp() {
        System.out.println(
            "Usage: hjUDPproxy <username> <password> <host_addr> "
            + "<tcp_port> <movie> <[udp_port | endpoint1]> <[player_port | endpoint2]>\n");

        System.out.println("<username>: username of the client making request");
        System.out.println("<password>: password of the client");
        System.out.println("<host_addr>: address where communications will occur");
        System.out.println("<tcp_port>: port that server is listening on");
        System.out.println("<movie>: requested movie");
        System.out.println( "<udp_port>: port where movie will be received from (on host_addr);" +
            "\n\talternatively endpoint1 depending on formatting");
        System.out.println( "<player_port>: port where movie will be streamed to (on host_addr);" +
            "\n\talternatively endpoint2 depending on formatting");
        System.out.println("<endpoint1>: endpoint for receiving stream");
        System.out.println("<endpoint2>: endpoint of media player\n");

        System.out.println("Ex: hjUDPproxy user1 password1 127.0.0.1 3333 cars 5555 9999");
        System.out.println("Ex: hjUDPproxy user2 password2 172.50.0.2 3333 cars " +
                                "172.50.0.2:5555 localhost:9999");
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
