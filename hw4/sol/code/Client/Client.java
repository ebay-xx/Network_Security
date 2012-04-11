import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*; 
import java.security.*;
import javax.crypto.*;
import java.security.interfaces.*;
import java.math.BigInteger;

class Client extends JFrame{
	
	public Client(){
    	super("SecTalk Client @ cliu70");
    	this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    
    	initConnectPanel();
    	initMsgShowPanel();
    	initMsgEditPanel();
    
    	Container pane = getContentPane();
    	pane.setLayout(new BorderLayout());
    	pane.add(connectPanel,BorderLayout.NORTH);
    	pane.add(msgShowPanel,BorderLayout.CENTER);
   		pane.add(msgEditPanel,BorderLayout.SOUTH);
    
    	pack();
    	setVisible(true);
    
    	try{
    		clientKeyRSA = new SKey_RSA();
    	}
    	catch(Exception e){System.out.println("Error when generating RSA key£º"+e);}   
  	}
  	
  	private void initConnectPanel(){
    	connectPanel = new JPanel();
    	connectPanel.setLayout(new FlowLayout());
    
    	JButton connectButton = new JButton("Connect");
    	connectButton.setFont(font);
    	connectButton.addActionListener(new ActionListener(){
    		public void actionPerformed(ActionEvent e){
    			connectServer(ipAddress.getText());
    		}
    	}); 
    
    	ipAddress = new JTextField(10);
    	ipAddress.setText("localhost");
     
    	connectPanel.add(connectButton);
    	connectPanel.add(ipAddress);
  	}
  
  	private void connectServer(String serverAddress){
		try { 
			clientMsg = new Socket(serverAddress,msgPort); 
			clientRSA = new Socket(serverAddress,RSAPort); 
			clientDES = new Socket(serverAddress,DESPort); 
			if(clientMsg.isBound()==true &&
				clientRSA.isBound()==true &&
				clientDES.isBound()==true) {
				msgShowArea.append("Successfully connected to the server£¡"+"\n");
				new keyThread(clientRSA, clientDES).start();
				new recThread(clientMsg).start();
			}
			else msgShowArea.append("Connection FAILED£¡"+"\n");
		} 
		catch(Exception e){ System.out.println("Error when connecting:"+e); } 
  	}

  	class keyThread extends Thread{
  		private ObjectInputStream ObjISDES;
  		private ObjectInputStream ObjISRSA;
  		private ObjectOutputStream ObjOSRSA;
  		byte[] bkeyDES;
  		Cipher cipher;
  	
  		public keyThread(Socket sRSA, Socket sDES) throws IOException{
  			ObjOSRSA = new ObjectOutputStream(sRSA.getOutputStream());
  			ObjISRSA = new ObjectInputStream(sRSA.getInputStream());
  			ObjISDES = new ObjectInputStream(sDES.getInputStream());
  			
			ObjOSRSA.writeObject(clientKeyRSA.getPublicKey());
			ObjOSRSA.flush();
		
			try{
				cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.UNWRAP_MODE, clientKeyRSA.getPrivateKey());
			}catch(Exception e){System.out.println("Cipher:"+e);}				
  		}
  	
  		public void run(){
  			try {
  				serverPBK = (RSAPublicKey) ObjISRSA.readObject();
  				ObjOSRSA.close();
  				ObjISRSA.close();
  			
  				bkeyDES = (byte[]) ObjISDES.readObject();
				keyDES = (SecretKey) cipher.unwrap(bkeyDES, "DES",Cipher.SECRET_KEY);
				ObjISDES.close();
				
				msgShowArea.append("Start Key exchange\n");
				msgShowArea.append("Client's Private Key£º" + byteToBinary(clientKeyRSA.getPrivateKey().getEncoded()) + "\n");	
				msgShowArea.append("Client's Public Key£º" + byteToBinary(clientKeyRSA.getPublicKey().getEncoded()) + "\n");
 				msgShowArea.append("Server's Public Key: " + byteToBinary(serverPBK.getEncoded()) + "\n");
				msgShowArea.append("DES Key£º" + byteToBinary(keyDES.getEncoded()) + "\n");	
				msgShowArea.append("Key exchange completed! You can send message now :)\n");	
				msgShowArea.setCaretPosition(msgShowArea.getText().length());
			}
  			catch(Exception e){System.out.println(e);} 								 	
  		}
  	}
  	
  	class recThread extends Thread{
  		private byte[] eData;
  		private byte[] data;
  		private byte[] eSData;
  		private byte[] sData;
  		private String str;
  	  	
		public recThread(Socket sMsg) throws IOException {
			ObjOSMsg=new ObjectOutputStream(sMsg.getOutputStream());
  			ObjISMsg=new ObjectInputStream(sMsg.getInputStream());
		}
	
		public void run(){
			try{ 
 				while(true){
 		 			eData = (byte[]) ObjISMsg.readObject();
 			 		data = SKey_DES.SEnc(keyDES, "DEC", eData);
 			  		str = new String(data);
 		 			eSData = (byte[]) ObjISMsg.readObject();
 					sData = SKey_DES.SEnc(keyDES, "DEC", eSData);
 		 			if(!Sign_n_Check.CheckSign(serverPBK, data, sData))
 			 			str = "Signature check FAILED! Invalid Data!";
 		 			msgShowArea.append("Server: "+str+"\n");
 		 			if(detailShow.isSelected()){
						msgShowArea.append("Encrypted message received£º" + byteToBinary(eData) + "\n");
						msgShowArea.append("Encrypted signature received£º" + byteToBinary(eSData) + "\n");
						msgShowArea.append("MD5withRSA signature info£º" + byteToBinary(sData) + "\n");	
					}
					msgShowArea.setCaretPosition(msgShowArea.getText().length());
  				}
 	 		}
 			catch(Exception e){System.out.println("Error when receiving message£º"+e);};
 		}
  	}

  	private void initMsgShowPanel(){
    	msgShowPanel = new JPanel();
    	msgShowPanel.setLayout(new BorderLayout());
    
    	JLabel label = new JLabel("Message: ");
    	label.setFont(font);
    
 		msgShowArea = new JTextArea(10,50);
 		msgShowArea.setEditable(false);
    	JScrollPane msgShowPane = new JScrollPane();
    	msgShowPane.setViewportView(msgShowArea);
    
    	msgShowPanel.add(label,BorderLayout.NORTH);
    	msgShowPanel.add(msgShowPane,BorderLayout.CENTER);
  	}

	
  	private void initMsgEditPanel(){
    	msgEditPanel = new JPanel();
    	msgEditPanel.setLayout(new BorderLayout());
    
    	JLabel label = new JLabel("Enter message here: ");
    	label.setFont(font);
        
    	msgEditArea = new JTextArea(5,50);
    	JScrollPane msgEditPane = new JScrollPane();
    	msgEditPane.setViewportView(msgEditArea);
    
    	JPanel buttonPanel = new JPanel();
    	JButton sendButton = new JButton("SEND"); 
    	sendButton.setFont(font);
    	sendButton.addActionListener(new ActionListener(){
    		public void actionPerformed(ActionEvent e){
    			try {
    				byte[] data = msgEditArea.getText().getBytes();
    				byte[] sData = Sign_n_Check.Sign(clientKeyRSA.getPrivateKey(), data);
					byte[] eData = SKey_DES.SEnc(keyDES, "ENC", data);
    				byte[] eSData = SKey_DES.SEnc(keyDES, "ENC", sData);
    			
					ObjOSMsg.writeObject(eData);
					ObjOSMsg.flush(); 
					ObjOSMsg.writeObject(eSData);
					ObjOSMsg.flush();
					msgShowArea.append("Client: "+msgEditArea.getText()+"\n");
					if(detailShow.isSelected()){
						msgShowArea.append("Encrypted message£º" + byteToBinary(eData) + "\n");
						msgShowArea.append("MD5WithRSA signature info£º" + byteToBinary(sData) + "\n");
						msgShowArea.append("Encrypted signature£º" + byteToBinary(eSData) + "\n");	
					}	   
					msgShowArea.setCaretPosition(msgShowArea.getText().length());
					msgEditArea.setText(null);			      
				}
				catch (Exception b){System.out.println("Error when sending message:"+b);};
    		}
    	});
    	buttonPanel.add(sendButton);
    	detailShow = new JCheckBox("Show encryption detail");  
    	buttonPanel.add(detailShow);
    
    	msgEditPanel.add(label,BorderLayout.NORTH);
    	msgEditPanel.add(msgEditPane,BorderLayout.CENTER);
    	msgEditPanel.add(buttonPanel,BorderLayout.SOUTH);
  	}

  	private static String byteToBinary (byte[] bytes){
  		BigInteger bi = new BigInteger(bytes);
  		return bi.toString(2);
  	}
  	  
  	private JPanel connectPanel;
	private JTextField ipAddress;
  	private JPanel msgShowPanel;
  	private JTextArea msgShowArea;
  	private JPanel msgEditPanel;
  	private JTextArea msgEditArea;
  	private JCheckBox detailShow;
  
  	private Socket clientMsg, clientRSA, clientDES;
	private static final int msgPort = 11268;
  	private static final int RSAPort = 11234;
  	private static final int DESPort = 11233;
  	private ObjectInputStream ObjISMsg;
  	private ObjectOutputStream ObjOSMsg;
  
  	private SKey_RSA clientKeyRSA;
  	private PublicKey serverPBK;
  	private SecretKey keyDES;
  
  	private Font font = new Font("Dialog",Font.BOLD,18);
}

class Sign_n_Check{	
    public static byte[] Sign(PrivateKey k, byte[] data) 
    		throws Exception{
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

    
    public static Key unwrapkey(
    	byte []wrapedkey,
     	PrivateKey privateKey,
     	String wrappedKeyAlgorithm,
     	int wrappedKeyType)throws Exception{
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

class ClientStart{
	public static void main(String[] args){
    	new Client();
	}
}    