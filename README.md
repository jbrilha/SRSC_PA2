# SRSC — Project Assignment #1

## Project Structure
- Developed entirely in a shell environment, with Java19
- To make development and testing easier, some of the provided testing files were given a package declaration but I do not count these as "changed lines" in the form, simply because they could be ommitted and the DSTP directory placed in the appropriate location for compilation and testing; In truth this was mostly because the terminal editor that I use needs proper declarations to not show errors during editing, and those got really annoying.
- The side effect of this is that when compiling and running the files, there's a bit more care to be had with the path used for the server/proxy/multicast, but that's what the helper scripts are for :D

## Testing streaming and multicasting
- To facilitate testing these services, there are a few helper scripts:
    * compile.sh — Due to the directory structure of TFTP-master, this _*only*_ compiles the Java files inside StreamingService and TestMulticast, as well as the DSTP classes
    * multicastReceiver.sh — Starts the Receiver service, defaults to 224.20.20.20:2000, but accepts the same arguments as the Receiver
    * multicastSender.sh — Starts the Sender service, defaults to 224.20.20.20:2000 with interval = 1, but accepts the same arguments as the Sender
    * proxy.sh — Starts the Proxy service, defaults to passing communication between localhost:10000 and localhost:9000, but accepts the same arguments as the Proxy
    * streamServer.sh — Starts the StreamServer service, defaults to streaming "cars.dat" to localhost:10000, but accepts the same arguments as the StreamServer
- There are also two docker-compose files, both of which grab whatever cryptoconfig.txt file that is inside of src:
    * docker-compose.multicast.yml — starts a multicast connection between the containers
    * docker-compose.stream.yml — starts the stream in one container, the proxy in another, and allows for VLC to listen on udp://@:5000
    
## Testing TFTP
- To facilitate testing TFTP, there are two helper scripts:
    * server.sh — Recompiles and starts the TFTP Server service
    * client.sh — Recompiles and starts the TFTP Client service, defaults to a (R)ead operation on localhost for the file "server1.jpg", but accepts same arguments as TFTPClient
- Note: changes made to the DSTPSocket classes are not recompiled unless the .class files are deleted so that's why I left these ones as "recompilers" and not just runners

## Example configurations
- There are examples matching all the configurations from the form in the "configs" directory, including the two that are invalid (and named as such)
- To test each one, copy them to the src directory of whichever service is being tested, and name them "cryptoconfig.txt", or change the respective DSTPSocket's constructor to call the CryptoHandler with the appropriate filename.

## Additional notes
- Due to the structure of the TFTP-master, the DSTP directory from the main PA1 src/ has been copied to the src/ of the TFTPClient and Server, but is entirely the same.
- Same applies for the cryptoconfig.txt and the libs directory which just contains the bouncycastle jar
