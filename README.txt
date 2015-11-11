
Hybrid cryptography - Asymmetric and Symmetric crypto systems together provide security for the data transmission over insecure medium. It works in two stages, in first stage the key to encrypt/decrypt the information is shared using RSA key pairs (Asymmetric Crypto). After the completion of first stage, the communication happens over second stage where the information is encrypted/decrypted using AES symmetric keys (Shared securely in first stage).

Running the program: (On localhost)

All six files (four classes and two key files) should be saved in the same directory.

Two terminal windows are required to simulate client server model.

In first terminal window:  Run the server program - $java Server
In second terminal window: Run the client program - $java Client

Key features used:

- java networking client and server sockets
- Threads.
- Java Serialisation.
- Java Cryptography Architecture

Security Algorithms Used:
RSA and AES


The proof of concept application consists of four java classes:

1. Server.java
2. Client.java
3. message.java
4. RSA.java


Compilation: Only Server and Client class needs compilation.


When the Client program is run, first stage of sharing the key takes place automatically.

After the first stage, both - Client and Server can send and receive messages.



IMP: 

1. The two key files - public.key and private.key needs to be in the same directory.
2. Port 8002 should be free to be used by this application.
3. If new kay pair is required, just compile and run RSA.java. It will create two new files.


############## To Run client and Server on Different machines ######

Files required on Client machine(in same directory):
1. Client.java
2. message.java
3. public.key
4. private.key

Usage : $ java Client [server IP]


Files required on Client machine(in same directory):
1. Server.java
2. message.java
3. public.key
4. private.key

Usage: $ java Server

Optional:
>>>> If new kay pair is required, just compile and run RSA.java. It will create two new files. Copy and paste the two key files on both - Server and Client.

