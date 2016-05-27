import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;

public class ChatServer implements Runnable
{  
	private ChatServerThread clients[] = new ChatServerThread[20];
	//private ServerSocket server_socket = null;
	private SSLServerSocket server_socket = null;
    private static Signature signature = null;
    private static KeyStore keystore = null;
    private static KeyStore[] clientkeys = null;
	private Thread thread = null;
	private int clientCount = 0;
    private static String alias = null;
    private static String aliasPub = null;

	public ChatServer(int port)
    	{  
		try
      		{  
      				SSLServerSocketFactory factory=(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();        			                	
            		// Binds to port and starts server
					System.out.println("Binding to port " + port);
            		//server_socket = new ServerSocket(port);  
            		server_socket=(SSLServerSocket) factory.createServerSocket(port);

                    String [] supported = factory.getSupportedCipherSuites();
                    server_socket.setEnabledCipherSuites(supported);

                    System.out.println("Server started: " + server_socket);
            		start();
        	}
      		catch(IOException ioexception)
      		{  
            		// Error binding to port
            		System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        	}
    	}
    
    	public void run()
    	{  
        	while (thread != null)
        	{  
            		try
            		{  
                		// Adds new thread for new client
                		System.out.println("Waiting for a client ..."); 
                		SSLSocket sslsocket=(SSLSocket) server_socket.accept();
                		addThread(sslsocket); 
            		}
            		catch(IOException ioexception)
            		{
                		System.out.println("Accept error: " + ioexception); stop();
            		}
        	}
    	}

   	public void start()
    	{  
        	if (thread == null)
        	{  
            		// Starts new thread for client
            		thread = new Thread(this); 
            		thread.start();
        	}
    	}
    
    	@SuppressWarnings("deprecation")
    	public void stop()
    	{  
        	if (thread != null)
        	{
            		// Stops running thread for client
            		thread.stop(); 
            		thread = null;
        	}
    	}
   
    	private int findClient(int ID)
    	{  
        	// Returns client from id
        	for (int i = 0; i < clientCount; i++)
            		if (clients[i].getID() == ID)
                		return i;
        	return -1;
    	}
    
    	public synchronized void handle(int ID, Message msg)
    	{  
            boolean isVerified = false; 
            String message = null;           
            try{
                byte[] originalMsg = msg.getOriginalMessage();
                byte[] signMsg = msg.getSignedMessage();
                String pubAlias = msg.getAlias();

                Certificate publicCert = null;
                int i = 0;

                while(publicCert == null){
                    publicCert = clientkeys[i++].getCertificate(pubAlias);
                }

                Signature verifySig = Signature.getInstance("SHA256withRSA");
                verifySig.initVerify(publicCert); 
                verifySig.update(originalMsg);
                isVerified = verifySig.verify(signMsg);                        

                if(!isVerified){
                    int leaving_id = findClient(ID);
                    for (i = 0; i < clientCount; i++)
                        if (i!=leaving_id)
                            clients[i].send("Client " +ID + " exits..");

                    remove(ID);
                }       

                message = new String(originalMsg);        
            }catch(Exception e){
                e.printStackTrace();
            }

            if (message.equals(".quit"))
            {  
                int leaving_id = findClient(ID);
                // Client exits
                clients[leaving_id].send(".quit");
                // Notify remaing users
                for (int i = 0; i < clientCount; i++)
                        if (i!=leaving_id)
                            clients[i].send("Client " +ID + " exits..");
                remove(ID);
            }
            else
                // Brodcast message for every other client online
                for (int i = 0; i < clientCount; i++)
                    clients[i].send(ID + ": " + message);  
    	}
    
    	@SuppressWarnings("deprecation")
    	public synchronized void remove(int ID)
    	{  
        	int pos = findClient(ID);
      
       	 	if (pos >= 0)
        	{  
            		// Removes thread for exiting client
            		ChatServerThread toTerminate = clients[pos];
            		System.out.println("Removing client thread " + ID + " at " + pos);
            		if (pos < clientCount-1)
                		for (int i = pos+1; i < clientCount; i++)
                    			clients[i-1] = clients[i];
            		clientCount--;
         
            		try
            		{  
                		toTerminate.close(); 
            		}
         
            		catch(IOException ioe)
            		{  
                		System.out.println("Error closing thread: " + ioe); 
            		}
         
            		toTerminate.stop(); 
        	}
    	}
    
    	private void addThread(SSLSocket socket)
    	{  
    	    	if (clientCount < clients.length)
        	{  
            		// Adds thread for new accepted client
            		System.out.println("Client accepted: " + socket);
            		clients[clientCount] = new ChatServerThread(this, socket, signature, aliasPub);
         
           		try
            		{  
                		clients[clientCount].open(); 
                		clients[clientCount].start();  
                		clientCount++; 
            		}
            		catch(IOException ioe)
            		{  
               			System.out.println("Error opening thread: " + ioe); 
            		}
       	 	}
        	else
            		System.out.println("Client refused: maximum " + clients.length + " reached.");
    	}
    
    
	public static void main(String args[])
   	{
        	ChatServer server = null;
        
        	if (args.length < 9)
            		// Displays correct usage for server
            		System.out.println("Usage: java ChatServer port crt password aliaspriv aliaspub (crtclient passclient)*");
        	else{
                try{
            		// Calls new server
                    keystore = KeyStore.getInstance("JKS");
                    char[] storePass = args[2].toCharArray();
                    alias = args[3];
                    aliasPub = args[4];

                    //load the key store from file system
                    FileInputStream fileInputStream = new FileInputStream(args[1]);
                    keystore.load(fileInputStream, storePass);
                    fileInputStream.close();

                    /***************************signing********************************/
                    //read the private key
                    KeyStore.ProtectionParameter keyPass = new KeyStore.PasswordProtection(storePass);
                    KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, keyPass);
                    PrivateKey privateKey = privKeyEntry.getPrivateKey();

                    //initialize the signature with signature algorithm and private key
                    signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(privateKey);

                    clientkeys = new KeyStore[(int)((args.length - 5) / 2)];
                    TrustManagerFactory trustManager = null;

                    for(int i = 5, j = 0; i < args.length; i += 2, ++j){
                        storePass = args[i + 1].toCharArray();
                        clientkeys[j] = KeyStore.getInstance("JKS");
                        clientkeys[j].load(new FileInputStream(args[i]), storePass);
                        trustManager = TrustManagerFactory.getInstance("SunX509");
                        trustManager.init(clientkeys[j]);
                    }

            		server = new ChatServer(Integer.parseInt(args[0]));
                }catch(Exception e){
                    e.printStackTrace();
                }
            }
    	}

}

class ChatServerThread extends Thread
{  
    private ChatServer       server    = null;
    private SSLSocket           socket    = null;
    private int              ID        = -1;
    private ObjectInputStream  streamIn  =  null;
    private ObjectOutputStream streamOut = null;
    private Signature signature = null;
    private String alias = null;

   
    public ChatServerThread(ChatServer _server, SSLSocket _socket, Signature _signature, String _alias)
    {  
        super();
        server = _server;
        socket = _socket;
        signature = _signature;
        alias = _alias;
        ID     = socket.getPort();
    }
    
    // Sends message to client
    @SuppressWarnings("deprecation")
    public void send(String msg)
    {   
        try
        {  
            byte[] dataInBytes = msg.getBytes("UTF-8");
            signature.update(dataInBytes);
            byte[] dataInBytes2 = signature.sign();
            
            Message sendMessage = new Message(dataInBytes, dataInBytes2, alias);
            
            streamOut.writeObject(sendMessage);
            streamOut.flush();
        }
       
        catch(IOException ioexception)
        {  
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    
    // Gets id for client
    public int getID()
    {  
        return ID;
    }
   
    // Runs thread
    @SuppressWarnings("deprecation")
    public void run()
    {  
        System.out.println("Server Thread " + ID + " running.");
      
        while (true)
        {  
            try
            {                
                server.handle(ID, (Message)streamIn.readObject());
            }
         
            catch(IOException ioe)
            {  
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            }
            catch(Exception e){
                e.printStackTrace();
            }
        }
    }
    
    
    // Opens thread
    public void open() throws IOException
    {  
        streamIn = new ObjectInputStream(new 
                        BufferedInputStream(socket.getInputStream()));
        streamOut = new ObjectOutputStream(new
                        BufferedOutputStream(socket.getOutputStream()));
        streamOut.flush();
    }
    
    // Closes thread
    public void close() throws IOException
    {  
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
    }
    
}
