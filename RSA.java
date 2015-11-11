/**
 * RSA.java
 * 
 * This program will be called by Server program. It is not required to individually.
 * 
 * Compile	 	$javac RSA.java 
 * 
 * 
 */



import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;


	/*
	 * RSA class
	 * 			will generate RSA key pair and save in files locally.
	 * 
	 * 
	 */

public class RSA {
		
		Key publicKey;
		Key privateKey;
		
		/*
		 * main method
		 * 			will instantiate an object of RSA class and call the createRSA method.
		 * 
		 */
	
		public static void main(String[] args) throws NoSuchAlgorithmException, GeneralSecurityException, IOException{
			
			System.out.println("Creating RSA class");
			RSA rsa = new RSA();
			rsa.createRSA();	
		}
		
		
		
		// ============ Generating key pair =======
		
		/*
		 * createRSA method
		 * 					will create RSA key pair.
		 * 					the keys will be saved as object in two separate files.
		 */
		
		void createRSA() throws NoSuchAlgorithmException, GeneralSecurityException, IOException{
		
			KeyPairGenerator kPairGen = KeyPairGenerator.getInstance("RSA");
			kPairGen.initialize(1024);
			KeyPair kPair = kPairGen.genKeyPair();
			publicKey = kPair.getPublic();
			System.out.println(publicKey);
			privateKey = kPair.getPrivate();
	 
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(kPair.getPublic(), RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = fact.getKeySpec(kPair.getPrivate(), RSAPrivateKeySpec.class);
			serializeToFile("public.key", pub.getModulus(), pub.getPublicExponent()); 				// this will give public key file
			serializeToFile("private.key", priv.getModulus(), priv.getPrivateExponent());			// this will give private key file
			
		}
			
		// ===== Save the keys with  specifications into files ==============
		/*
		 * serializeToFile method
		 * 						will create an ObjectOutput Stream and 
		 * 						save the elements of key pairs into files locally.
		 * 
		 */

		void serializeToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		  	ObjectOutputStream ObjOut = new ObjectOutputStream( new BufferedOutputStream(new FileOutputStream(fileName)));

		  	try {
		  		ObjOut.writeObject(mod);
		  		ObjOut.writeObject(exp);
		  		System.out.println("Key File Created: " + fileName);
		 	 } catch (Exception e) {
		 	   throw new IOException(" Error while writing the key object", e);
		 	 } finally {
		 	   ObjOut.close();
		 	 }
			}
			
}
