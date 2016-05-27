import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Timer;
import java.util.TimerTask;


public class ChatClient implements Runnable
{  
    //private Socket socket              = null;
    private SSLSocket socket 	   	   = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private int periodKeys = 5000; //milisegundos


    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            /*
             * Load Client Private Key
             */
            KeyStore clientKeys = KeyStore.getInstance("JKS");
            clientKeys.load(new FileInputStream("demo/plainclient.jks"),"password".toCharArray());
            KeyManagerFactory clientKeyManager = KeyManagerFactory.getInstance("SunX509");
            clientKeyManager.init(clientKeys,"password".toCharArray());

            /*
             * Load Server Private Key
             */
            KeyStore serverPub = KeyStore.getInstance("JKS");
            serverPub.load(new FileInputStream("demo/serverpub.jks"),"password".toCharArray());
            TrustManagerFactory trustManager = TrustManagerFactory.getInstance("SunX509");
            trustManager.init(serverPub);

            /*
             * Use keys to create SSLSoket
             */
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(clientKeyManager.getKeyManagers(), trustManager.getTrustManagers(), SecureRandom.getInstance("SHA1PRNG"));
            socket = (SSLSocket)ssl.getSocketFactory().createSocket(serverName, serverPort);
            //socket.startHandshake();

            // Establishes connection with server (name and port)
            //socket = new Socket(serverName, serverPort);
            //SSLSocketFactory factory=(SSLSocketFactory) SSLSocketFactory.getDefault();
        	//socket=(SSLSocket) factory.createSocket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
            start();
        }
        
        catch(UnknownHostException uhe)
        {  
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        }
      
        catch(Exception ioexception)
        {  
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage()); 
        }
        
   }

    
   @SuppressWarnings("deprecation")
   public void run(){

        Timer timer = new Timer();
        timer.schedule(new RemindTask(socket), 0, periodKeys);
       
       while (thread != null)
       {  
           try
           {  
               // Sends message from console to server
               streamOut.writeUTF(console.readLine());
               streamOut.flush();
           }
         
           catch(Exception ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }
    
    
    public void handle(String msg)
    {  
        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(msg);
    }
    
    // Inits new client thread
    public void start() throws IOException
    {  
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
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
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }
    
}

class ChatClientThread extends Thread
{  
    private SSLSocket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;

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
            streamIn  = new DataInputStream(socket.getInputStream());
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
                client.handle(streamIn.readUTF());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
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

