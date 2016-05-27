import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Timer;
import java.util.TimerTask;

public class ChatClient implements Runnable
{  
    //private Socket socket              = null;
    private SSLSocket socket 	   	   = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private ObjectOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private static Signature signature = null;
    private static KeyStore keystore = null;
    private static KeyStore serverkey = null;
    private static String alias = null;
    private static String aliasPub = null;
    private int periodKeys = 30000; //ms
    private Timer timer = null;

    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            //socket = new Socket(serverName, serverPort);
            SSLSocketFactory factory=(SSLSocketFactory) SSLSocketFactory.getDefault();
        	socket=(SSLSocket) factory.createSocket(serverName, serverPort);

            String [] supported = factory.getSupportedCipherSuites();
            socket.setEnabledCipherSuites(supported);

            System.out.println("Connected to server: " + socket);
            start();
        }
        
        catch(UnknownHostException uhe)
        {  
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        }
      
        catch(IOException ioexception)
        {  
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception); 
        }
        
   }
    
   @SuppressWarnings("deprecation")
   public void run()
   {  
        timer = new Timer();
        timer.schedule(new RemindTask(socket), 0, periodKeys);

       while (thread != null)
       {  
            String msg = null;
           try
           {  
                msg = console.readLine();
                byte[] dataInBytes = msg.getBytes("UTF-8");
                signature.update(dataInBytes);
                byte[] dataInBytes2 = signature.sign();
                
                Message sendMessage = new Message(dataInBytes, dataInBytes2, aliasPub);                

                // Sends message from console to server
                streamOut.writeObject(sendMessage);
                streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
           catch(Exception e){
               e.printStackTrace();
            }
       }
    }
    
    
    public void handle(Message msg)
    {          
        boolean isVerified = false;
        String message = null;
        try{
            byte[] originalMsg = msg.getOriginalMessage();
            byte[] signMsg = msg.getSignedMessage();
            String pubAlias = msg.getAlias();
            
            Certificate publicCert = serverkey.getCertificate(pubAlias);             
            Signature verifySig = Signature.getInstance("SHA256withRSA");
            verifySig.initVerify(publicCert); 
            verifySig.update(originalMsg);
            isVerified = verifySig.verify(signMsg);

            if(!isVerified){
                System.exit(0);
            }

            message = new String(originalMsg);
        }catch(Exception e){
            e.printStackTrace();
        }        

        // Receives message from server
        if (message.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(message);
    }
    
    // Inits new client thread
    public void start() throws IOException
    {                   
        console   = new DataInputStream(System.in);                
        streamOut = new ObjectOutputStream(socket.getOutputStream());  
        //console.readLine();            
        if (thread == null)
        {              
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);                   
            thread.start();
        }
    }
    
    // Stops client thread
    @SuppressWarnings("deprecation")
    public void stop()
    {  
        if (thread != null)
        {  
            thread.stop();  
            thread = null;
            timer.cancel();
            timer.purge();
        }
        try
        {  
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();

        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing thread..."); }
            client.close();  
            client.stop();
        }
   
    
    public static void main(String args[])
    {
        ChatClient client = null;
        if (args.length != 8)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port crt password aliaspriv aliaspub crtserv passserv");
        else{
            try{
                // Calls new client
                keystore = KeyStore.getInstance("JKS");
                char[] storePass = args[3].toCharArray();
                char[] servPass = args[7].toCharArray();

                alias = args[4];
                aliasPub = args[5];

                FileInputStream fileInputStream = new FileInputStream(args[2]);
                keystore.load(fileInputStream, storePass);
                fileInputStream.close();

                KeyStore.ProtectionParameter keyPass = new KeyStore.PasswordProtection(storePass);
                KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, keyPass);
                PrivateKey privateKey = privKeyEntry.getPrivateKey();

                signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);

                serverkey = KeyStore.getInstance("JKS");
                serverkey.load(new FileInputStream(args[6]), servPass);
                TrustManagerFactory trustManager = TrustManagerFactory.getInstance("SunX509");
                trustManager.init(serverkey);

                client = new ChatClient(args[0], Integer.parseInt(args[1]));
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }
    
}

class ChatClientThread extends Thread
{  
    private SSLSocket           socket   = null;
    private ChatClient       client   = null;
    private ObjectInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, SSLSocket _socket)
    {  
        client   = _client;
        socket   = _socket;
        open();  
        start();
    }
   
    public void open()
    {  
        try
        {  
            streamIn  = new ObjectInputStream(socket.getInputStream());
        }
        catch(IOException ioe)
        {  
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }
    
    public void close()
    {  
        try
        {  
            if (streamIn != null) streamIn.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing input stream: " + ioe);
        }
    }
    
    public void run()
    {  
        while (true)
        {   try
            {          
                client.handle((Message)streamIn.readObject());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
            catch(ClassNotFoundException e){
                
            }
        }
    }
}

class RemindTask extends TimerTask {

    SSLSocket socket;

    RemindTask(SSLSocket socket){
        this.socket = socket;
    }

    public void run() {
        System.out.println("[LOG] - New handshake");
        try{
            socket.startHandshake();
        }catch(Exception e){
            System.out.println("Error starting Handshake: " + e.getMessage());
        }
    }
  }
