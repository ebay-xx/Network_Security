import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*; 
import java.security.*;
import javax.crypto.*;
import java.security.interfaces.*;
import java.math.BigInteger;

class Server extends JFrame{
	public Server(){
    	
    	try{
    		serverKeyRSA = new SKey_RSA();
    		SKey_DES skeyDES = new SKey_DES();
    		keyDES = skeyDES.getSecretKey();
    		serverMsg = new ServerSocket(msgPort);
    		serverRSA = new ServerSocket(RSAPort);
    		serverDES = new ServerSocket(DESPort);
  			System.out.println("Server is running, waiting for client..\n");
    		new keyThread(serverRSA.accept(), serverDES.accept()).start();
    		new recThread(serverMsg.accept()).start();
    	}
    	catch(Exception e){System.out.println("server.accept:"+e);};
    }
  
  	class keyThread extends Thread{
  		private ObjectOutputStream ObjOSDES;
  		private ObjectOutputStream ObjOSRSA;
  		private ObjectInputStream ObjISRSA;
  		byte[] keyDESbyte;
  	
  		public keyThread(Socket sRSA, Socket sDES) throws IOException{  		
  			ObjOSDES = new ObjectOutputStream(sDES.getOutputStream());
  			ObjOSRSA = new ObjectOutputStream(sRSA.getOutputStream());
  			ObjISRSA = new ObjectInputStream(sRSA.getInputStream());
  		}
  	
  		public void run(){
  			try {
				clientPBK = (RSAPublicKey) ObjISRSA.readObject();
  				
				ObjOSRSA.writeObject(serverKeyRSA.getPublicKey());
				ObjOSRSA.flush();
				ObjOSRSA.close();
				ObjISRSA.close();
				
 				keyDESbyte = SKey_RSA.wrapkey(keyDES, clientPBK);
 				ObjOSDES.writeObject(keyDESbyte);
 				ObjOSDES.flush();
 				ObjOSDES.close();
				
				System.out.println("New client connecting...\nStart key exchange...\n");
				System.out.println("Key exchange successful!\nPrinting key information...\n");
				System.out.println("Server's Private Key£º" + byteToBinary(serverKeyRSA.getPrivateKey().getEncoded()) + "\n");
				System.out.println("Server's Public Key£º" + byteToBinary(serverKeyRSA.getPublicKey().getEncoded()) + "\n");
				System.out.println("Client's Public Key£º" + byteToBinary(clientPBK.getEncoded()) + "\n");
				System.out.println("DES Key£º" + byteToBinary(keyDES.getEncoded()) + "\n");
				System.out.println("Connection successfully established!\n");
				
  			}
  			catch(Exception e){System.out.println("keyThread:"+e);} 								 	
  		}
  	}
  
  	class recThread extends Thread{
  		private byte[] eData;
  		private byte[] data;
  		private byte[] eSData;
  		private byte[] sData;
  		private String str;
  		  	
		public recThread(Socket c) throws IOException {
			ObjOSMsg= new ObjectOutputStream(c.getOutputStream());
  			ObjISMsg= new ObjectInputStream(c.getInputStream());
		}
	
		public void run(){
 			try{ 
 				while(true){
 		 			eData = (byte[]) ObjISMsg.readObject();
 			 		data = SKey_DES.SEnc(keyDES, "DEC", eData);
 			  		str = new String(data);
 		 			eSData = (byte[]) ObjISMsg.readObject();
 					sData = SKey_DES.SEnc(keyDES, "DEC", eSData);
 		 			if(!Sign_n_Check.CheckSign(clientPBK, data, sData))
 			 			str = "Signature check FAILED! Invalid Data!";
 		 			System.out.println("Client: "+str+"\n");
					System.out.println("Encrypted message received: " + eData + "\n");
					System.out.println("Encrypted signature received: " + eSData +"\n");
					System.out.println("MD5withRSA signature info: " + sData + "\n");
					
					sData = Sign_n_Check.Sign(serverKeyRSA.getPrivateKey(), data);
					eData = SKey_DES.SEnc(keyDES, "ENC", data);
    				eSData = SKey_DES.SEnc(keyDES, "ENC", sData);
					ObjOSMsg.writeObject(eData);
					ObjOSMsg.flush(); 
					ObjOSMsg.writeObject(eSData);
					ObjOSMsg.flush();
					System.out.println("Server has echoed message back.\n\n---------------------------------------\n");
 				}
 			}
 			catch(Exception e){System.out.println("Error when receiving message£º"+e);};
 		}
  	}

 
		
  	private static String byteToBinary (byte[] bytes){
  		BigInteger bi = new BigInteger(bytes);
  		return bi.toString(2);
  	}
  
  	private JPanel msgShowPanel;
  	private JTextArea msgShowArea;
  	private JPanel msgEditPanel;
  	private JTextArea msgEditArea;
  	private JCheckBox detailShow;
  	
  	private ServerSocket serverMsg, serverRSA, serverDES;
  	private static final int msgPort = 11268;
  	private static final int RSAPort = 11234;
  	private static final int DESPort = 11233;
  	private ObjectInputStream ObjISMsg;
  	private ObjectOutputStream ObjOSMsg;
  
  	private SKey_RSA serverKeyRSA;
  	private PublicKey clientPBK;
  	private SecretKey keyDES;
}

class Sign_n_Check{	
    public static byte[] Sign(PrivateKey k, byte[] data) throws Exception{
        RSAPrivateKey prk = (RSAPrivateKey) k;
        Signature s = Signature.getInstance("MD5WithRSA");
        s.initSign(prk);
        s.update(data);
        return s.sign();
    }
    
    public static boolean CheckSign(PublicKey k, byte[] data, byte[] signeddata) 
            throws Exception{
        RSAPublicKey pbk = (RSAPublicKey) k;
        Signature s = Signature.getInstance("MD5WithRSA");
        s.initVerify(pbk);
        s.update(data);
        return s.verify(signeddata);
    }
}

class SKey_DES{
    public SKey_DES() throws Exception{
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(56);
        sKey = kg.generateKey();
    }
        
    public static byte[] SEnc(SecretKey k, String mode, byte[] data) 
            throws Exception{
        Cipher cp = Cipher.getInstance("DES");
        if(mode.equals("DEC"))
            cp.init(Cipher.DECRYPT_MODE, k);
        else 
            cp.init(Cipher.ENCRYPT_MODE, k);
        return cp.doFinal(data);
    }
    
    public SecretKey getSecretKey(){
    	return sKey;
    }
    
    private SecretKey sKey;		
}

class SKey_RSA {
	public SKey_RSA() throws Exception{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.genKeyPair();
        pbkey = kp.getPublic();
        prkey = kp.getPrivate();
    }
    
 	public static byte [] wrapkey(Key key, PublicKey publicKey)
 		throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.WRAP_MODE, publicKey);
		return (cipher.wrap(key));
	}

    
    public static Key unwrapkey(byte []wrapedkey, PrivateKey privateKey, String wrappedKeyAlgorithm, int wrappedKeyType)throws Exception{
		 Cipher cipher = Cipher.getInstance("RSA");
		 cipher.init(Cipher.UNWRAP_MODE, privateKey);
		 return (cipher.unwrap(wrapedkey, wrappedKeyAlgorithm, wrappedKeyType));
    }    
    
    public PublicKey getPublicKey(){
    	return pbkey;
    }
    
    public PrivateKey getPrivateKey(){
    	return prkey;
    }
    
    private PublicKey pbkey;
    private PrivateKey prkey;
}

class ServerStart{
  	public static void main(String[] args){
    	new Server();
  	}
}    