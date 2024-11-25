## Dates:
28 / 29 Nov — Form opens
11 Dec — Final delivery


                    
  Proxy         |   ----------- request to see a movie ------------>            | Stream Server
                |                                                               |
  Alice         |   <-----------------------------------------------            | Bob
                |   RandomChallenge + RamdomInitCounter + RandomSalt            |
 CERTalice-CA   |                                                               | pubKey of CA
                |          ----------------------------------->                 |
                |          PBE H(pwd),ctr,salt[(randChall + 1)] | CERTalice-CA  |
                |                                                               |
                |          <-----------------------------------                 |
                |          OK, Ek[cryptoconfig], EkpubA(k), SIGprivkSS(X)       |
                |                                                               |
                |          --------------------------------------->             |
                |                   El(OK, GO, UDP-Port)                        |


                |   PBE H(pwd), nonce1, nonce2, (...,...), nonce3        ----> this whole thing is X
    append with:        || DigiSignKpriv(X) || HMAC(X, Y)
                                /\              H(nonce3)
                                ||    
                                 Y

EKpubA(kS) || EkS(cryptoconfig, YB)                 -> YB is Bob's Diffie-Hellman public number from a tag
                                                        (optional)
                            


server discards already used numbers,
    can store in file with as many as needed for given communication?


PBE: password-based encryption
    with pwd hash, the counter and the salt

E: e.g. AES encryption
    with key generated server-side


 ## 15/11

TCP based handshake, send a bunch of nonces
after cryptoconfig is shared via handshake then do the other shit over UDP
