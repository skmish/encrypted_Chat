
/**
 * Client.java
 * 
 *  @author Sarvagya Kumar Mishra
 *  
 *  Dependency : Sever.java, message.java, RSA.java
 *  
 *  Run Client only after running the Server program.
 *  
 * Compile	 	$javac Client.java 
 * Run 			$java Client
 *
 *  References:
 *  http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html
 *  http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
 * 
 */


import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

//import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/*
 * 
 * Public class Client.
 * 
 *  The Client will send encrypted message to the server.
 *  
 *  First message sent to server is the AES key. 
 *  
 *  After that client will ask for input. The provided input will be encrypted using the AES key and will be send to server.
 *  
 * 
 */

public class Client {

	private ObjectOutputStream sOutput;
	private ObjectInputStream sInput;

	private Socket socket;
	private String server;
	private int port;
	private Cipher cipher1;
	private Cipher cipher2;
	int i = 0;
	message m;
	SecretKey AESkey;
	message toSend;
	static String IV = "AAAAAAAAAAAAAAAA";
	
	
	
	// ===== THE CONSTRUCTOR ==========
	
	Client (String server, int port){ 						
	this.server = server;
	this.port = port;
	}
	
	
	
	/*
	 * 
	 * The main method
	 * 
	 * Creates the an instance of Client class with provided server address and TCP port to establish the socket conenction.
	 * 
	 * @param 
	 * 			Command Line arguments.
	 * 
	 * Program Flow : 	
	 * 
	 * 		MAIN --> start() & getKey()
	 * 		start() ---> sendToServer Thread
	 * 		sendToServer Thread ---> EncryptSecretKey() or encryptData(string)
	 * 
	 * 
	 */
	
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		
		String serverAddress;
	
		int portNumber = 8002;
		if(args.length < 1){
		System.out.println("#############################################################");
		System.out.println("# 															 ");
		System.out.println("# Usage: $ java Client [sever ip]							 ");
		System.out.println("# 															 ");
		System.out.println("# e.g. $ java Client 192.168.1.1																 ");
		System.out.println("# 							 								 ");
		System.out.println("# NO ARGUMENT REQUIRED IF SERVER RUNNING ON LOCALHOST		 ");
		System.out.println("# 															 ");
		System.out.println("#############################################################");
		
		serverAddress = "localhost";
		}
		else{
			serverAddress = args[0];
		}
		Client client = new Client(serverAddress, portNumber);
		client.generateAESkey();
		client.start();
	}
	
	/*
	 * the start method.
	 * 				establishes a socket connection with the server.
	 * 
	 * 
	 */
	
	void start() throws IOException{
		socket = new Socket(server, port);
		System.out.println("connection accepted " + socket.getInetAddress() + " :"  + socket.getPort());
		
		
		sInput = new ObjectInputStream(socket.getInputStream());
		sOutput = new ObjectOutputStream(socket.getOutputStream());
		
		new sendToServer().start();
		new listenFromServer().start();
	}
	
	
	
	/*
	 * 
	 *  listenFromServer method.
	 *  						Will receive the message from server and call the decryption method.
	 * 
	 * 
	 */
	
	

	class listenFromServer extends Thread {
		public void run(){
			while(true){
        try{
     m = (message) sInput.readObject();
       decryptMessage(m.getData());
      } catch (Exception e){
       		e.printStackTrace();
              System.out.println("connection closed");
                }
      	}
	}
	}

	
	
	/*
	 * sendToServer Class. Extends the thread class. Runs continuously.
	 * 
	 * 						Will send encrypted messages to the server.
	 * 						The first message sent to server will be encrypted AES key. The same key will be used by server to decrypt the future messages.
	 * 
	 * 						Once the AES key is shared, the client Will accept console inputs and encrypt it before sending to server.
	 * 
	 * 
	 */
	
	
	class sendToServer extends Thread {
        public void run(){
        	while(true){
        try{
	
        if (i == 0){	
        	toSend = null;
   
    	toSend = new message(encryptAESKey());
		sOutput.writeObject(toSend);
        	i =1;
        	}					
        
        else{
        	
        	System.out.println("CLIENT: Enter OUTGOING message > ");
			Scanner sc = new Scanner(System.in);
			String s = sc.nextLine();
			toSend = new message(encryptMessage(s));
			sOutput.writeObject(toSend);
        	}
        	
        } catch (Exception e){
              e.printStackTrace();
                System.out.println("No message sent to server");
                break;
                }
        	}
        }
	}

	
	/*
	 * //============== Create AES Key =================================
	 * 
	 * generateAESkey method
	 * 
	 * 						Called by main method, generates the AES key for encryption / decryption of the messages exchanged between client and server.
	 */
	
	void generateAESkey() throws NoSuchAlgorithmException{
	AESkey = null;
	KeyGenerator Gen = KeyGenerator.getInstance("AES");
	Gen.init(128);
	AESkey = Gen.generateKey();
	System.out.println("Genereated the AES key : " + AESkey);
	}
	
	
	
	/*
	 * // ====== Read RSA Public key to Encrypt the AES key  ==================
	 * 
	 * encryptAESKey method.
	 * 
	 * 						Will encrypt the AES key generated by generateAESkey method. It will also calculate the time taken for encrypting the AES key using RSA encryption method.
	 * 
	 * 						To encrypt the AES key, this method will read RSA public key from the RSA public = private key pairs saved in the same directory.
	 * 							
	 * 						Dependency: the public key  file "public.key" should be saved in the same directory. (Performed by server.java class)
	 * 	
	 */
		

	private byte[] encryptAESKey (){
		cipher1 = null;
    	byte[] key = null;
  	  try
  	  {
		 PublicKey pK = readPublicKeyFromFile("public.key");
	 	  System.out.println("Encrypting the AES key using RSA Public Key" + pK);
   	     // initialize the cipher with the user's public key
   	     cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
   	    
   	     cipher1.init(Cipher.ENCRYPT_MODE, pK );
   	     long time1 = System.nanoTime();
   	     key = cipher1.doFinal(AESkey.getEncoded());   // this encrypted key will be sent to the server.
   	     long time2 = System.nanoTime();
   	     long totalRSA = time2 - time1;
   	     System.out.println("Time taken by RSA Encryption (Nano Seconds) : " + totalRSA);
   	     i = 1;
   	 	}
  	  
   	 catch(Exception e ) {
    	    System.out.println ( "exception encoding key: " + e.getMessage() );
    	    e.printStackTrace();
   	 		}
  	  return key;
  	  } 
	
	
		/*
		 * //============= Encrypt Data to send =================
		 * 
		 * encryptMessage method
		 * 						Encrypts the string input using AES encryption with AES key generated by generateAESkey method.
		 * 
		 * @param 	String s 
		 * 					Input string to encrypt
		 * 
		 * Returns byte array as output.
		 * 
		 */

	
		private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException, 
							InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
											BadPaddingException{
		cipher2 = null;
    	byte[] cipherText = null;
    	cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    	
    	cipher2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()) );
    	long time3 = System.nanoTime();
    	cipherText = cipher2.doFinal(s.getBytes());
    	long time4 = System.nanoTime();
		long totalAES = time4 - time3;
		System.out.println("Time taken by AES Encryption (Nano Seconds) " + totalAES);
   	   return cipherText;
	}
	
		
	/*
	 * //=========== Decipher the received message with AES key =================
	 * 
	 * decryptMessage method, will decrypt the cipher text received from server. Currently disabled, can be enabled for two way communication.
	 * 
	 * @param byte[] data
	 * 					takes the byte array of encrypted message as input. Returns plain text.
	 * 
	 * 	
	 */
	
		
		private void decryptMessage(byte[] encryptedMessage) {
	        cipher2 = null;
	        try
	        {
	            cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            cipher2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
	             byte[] msg = cipher2.doFinal(encryptedMessage);		            
	             System.out.println("CLIENT: INCOMING Message From Server   >> " + new String(msg));
	             System.out.println("CLIENT: Enter OUTGOING message > ");
	        }
	        
	        catch(Exception e)
	         {
	        	e.getCause();
	        	e.printStackTrace();
	        	System.out.println ( "Exception genereated in decryptData method. Exception Name  :"  + e.getMessage() );
	            }
	    }
	
		
		
	/*
	 * closeSocket method  	//============== To close all the sockets and streams.===================
	 * 						Closes the input/output streams and sockets.
	 * 
	 * 
	 */
		

	public void closeSocket() {
		try{
	if(sInput !=null) sInput.close();
	if(sOutput !=null) sOutput.close();
	if(socket !=null) socket.close();
		}catch (IOException ioe){
			System.out.println("Error in Disconnect methd");
			}
		}
	
	
		/*
		 *  // ===================== Reading RSA public key from  file ===============
		 * 
		 * readPublicKeyFromFile method.
		 * 
		 * 								Will read the RSA public key from the file "public.key" 
		 * 								on the same directory to encrypt the AES key.
		 * 
		 */
	
	
	
		PublicKey readPublicKeyFromFile(String fileName) throws IOException {
		
	 	FileInputStream in = new FileInputStream(fileName);
	  	ObjectInputStream oin =  new ObjectInputStream(new BufferedInputStream(in));

	  	try {
	  	  BigInteger m = (BigInteger) oin.readObject();
	  	  BigInteger e = (BigInteger) oin.readObject();
	  	  RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m, e);
	  	  
	  	  KeyFactory kF = KeyFactory.getInstance("RSA");
	  	  PublicKey pubK = kF.generatePublic(keySpecifications);
	  	  return pubK;
	  	} catch (Exception e) {
	  		  throw new RuntimeException("Some error in reading public key", e);
	  	} finally {
	 	   oin.close();
	 	 }
		}
}



