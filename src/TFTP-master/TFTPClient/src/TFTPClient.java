
import SHP.*; // PA2: added import
import java.net.InetAddress;
import java.net.UnknownHostException;
class UseException extends Exception {
	public UseException() {
		super();
	}

	public UseException(String s) {
		super(s);
	}
}

public class TFTPClient {
	public static void main(String argv[]) throws TftpException, UseException {
        // PA2: new arguments
        String username = "";
        String password = "";
        int tcp_port = 0;
		String host = "";
		String fileName = "";
		String mode="octet"; //default mode
		String type="";
		try {
			// Process command line
			if (argv.length == 0)
				throw new UseException("--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]" );
			//use default mode(octet)
			if(argv.length == 6){  // PA2: parsing new arguments
                username = argv[0];
                password = argv[1];
				host =argv[2];
                tcp_port = Integer.parseInt(argv[3]);
			    type = argv[argv.length - 2];
			    fileName = argv[argv.length - 1];}
			//use other modes
			else if(argv.length == 7){ // PA2: parsing new arguments
                username = argv[0];
                password = argv[1];
				host = argv[2];
                tcp_port = Integer.parseInt(argv[3]);
				mode =argv[argv.length-1];
				type = argv[argv.length - 3];
				fileName = argv[argv.length - 2];
			}
			else throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");
			
            SHPClient sc = new SHPClient(host, tcp_port);
            CryptoConfig cc = sc.handshake(username, password, fileName, 6973); // PA2: SHP handshake udp port has to be 6973 set here or server-side
			
			InetAddress server = InetAddress.getByName(host);
			
			//process read request
			if(type.matches("R")){
				TFTPclientRRQ r = new TFTPclientRRQ(server, fileName, mode, cc);} // PA2: pass in CryptoConfig
			//process write request
			else if(type.matches("W")){
				TFTPclientWRQ w = new TFTPclientWRQ(server, fileName, mode, cc); // PA2: pass in CryptoConfig
			}
			else{throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");}
			
		} catch (UnknownHostException e) {
			System.out.println("Unknown host " + host);
		} catch (UseException e) {
			System.out.println(e.getMessage());
		}
	}
}
