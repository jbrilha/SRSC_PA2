# SRSC — Project Assignment #2

## Project Structure
- Developed entirely in a shell environment, with Java19
- To make development and testing easier, some of the provided testing files were given a package declaration but I do not count these as "changed lines" in the form, simply because they could be ommitted and the DSTP directory placed in the appropriate location for compilation and testing; In truth this was mostly because the terminal editor that I use needs proper declarations to not show errors during editing, and those got really annoying.
- The side effect of this is that when compiling and running the files, there's a bit more care to be had with the path used for the server/proxy/multicast, but that's what the helper scripts are for :D

## Testing streaming
- To facilitate testing these services, there are a few helper scripts:
    * compile.sh — Due to the directory structure of TFTP-master, this _*only*_ compiles the Java files inside StreamingService, as well as the DSTP and SHP classes
    * proxy.sh — Starts the Proxy service, defaults to having SHP handshake on TCP port 3333 (default in the SHPServer as the assignment spec said not to pass arguments to the streamServer) for user1@email.com with password1 on localhost, requesting movie cars.dat and passing communication between port 10000 and port 9000; accepts the same arguments as hjUDPproxy.java
    * streamServer.sh — Starts the StreamServer service
- There is also a docker-compose files, which grabs whatever ciphersuite.conf file that is inside of src:
    * docker-compose.stream.yml — starts the stream in one container, the proxy in another, and allows for VLC to listen on udp://@:9000
    
## Testing TFTP
- To facilitate testing TFTP, there are two helper scripts:
    * server.sh — Recompiles and starts the TFTP Server service
    * client.sh — Recompiles and starts the TFTP Client service, defaults to a (R)ead operation on localhost for the file "server1.jpg", but accepts same arguments as TFTPClient
- Note: changes made to the DSTPSocket classes are not recompiled unless the .class files are deleted so that's why I left these ones as "recompilers" and not just runners
### TFTP Client and Server are now dockerized!
* docker-compose.TFTP.yml (located in src/TFTP-master) runs the server continuously and spawns a client container to request a file
* The client commands can be swapped in the docker-compose.TFTP.yml file and a new client can be deployed with:

```docker compose -f docker-compose.TFTP.yml up --build client```

   to have it download a different file from the same server that was already up.

## Example ciphersuites
- Same configs from PA1 are now in the ciphersuites directory with the keys removed, as they are now derived from the Diffie-Hellman agreement generated secret
- To test each one, copy them to the src directory of whichever service is being tested, and name them "ciphersuite.conf"

## Additional notes
- Due to the structure of the TFTP-master, the DSTP and SHP directories from the main PA2 src/ have been copied to the src/ of the TFTPClient and Server, but are entirely the same except for the SHPServer that now validates the request for different files.
- Same applies for the ciphersuite.conf and the libs directory which just contains the bouncycastle jar
- Request confirmation (aka checking if a file exists) is hardcoded in the SHP servers, so for testing other files the validateRequest method would need to be changed
- TFTP still only works one way (client reads from server, but can't write to it) but that is unrelated to the SHP handshake so I will not lose (more) sleep over it, sorry!
