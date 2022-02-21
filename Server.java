import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.Signature;
import java.util.*;

class Post {
    private String id;
    private String msg;
    private String timeStamp;

    Post(String id, String msg, String timeStamp) {
        this.id = id;
        this.msg = msg;
        this.timeStamp = timeStamp;
    }

    public String getId() {
        return id;
    }

    public String getMsg() {
        return msg;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public String toString() {
        StringBuilder s = new StringBuilder("");
        s.append("Sender: ");
        s.append(id);
        s.append("\n");
        s.append("Time: ");
        s.append(timeStamp);
        s.append("\n");
        s.append("Message: ");
        s.append(msg);
        s.append("\n\n");

        return s.toString();
    }
}

class ServerClient implements Runnable {
    private Socket s;
    private List<Post> posts;

    ServerClient(Socket s, List<Post> posts) {
        this.s = s;
        this.posts = posts;
    }

    public void run() {
        try {
            try (DataOutputStream dout = new DataOutputStream(s.getOutputStream());
                    DataInputStream din = new DataInputStream(s.getInputStream())) {

                dout.writeInt(posts.size());
                for (Post p : posts) {
                    dout.writeUTF(p.getId());
                    dout.writeUTF(p.getMsg());
                    dout.writeUTF(p.getTimeStamp());
                    dout.flush();
                }

                if (!din.readBoolean())
                    return;

                String senderId = din.readUTF();
                if (!Server.users.containsKey(senderId)) {
                    RSAKeyGen.generateKeys(new String[] { senderId });
                    Server.users.put(senderId, true);
                }
                String recvrId = din.readUTF();
                if (!recvrId.equals("all")) {
                    if (!Server.users.containsKey(recvrId)) {
                        RSAKeyGen.generateKeys(new String[] { recvrId });
                        Server.users.put(recvrId, true);
                    }
                }
                dout.writeBoolean(true);

                String msg = din.readUTF();
                String timeStamp = din.readUTF();
                byte[] sign = din.readAllBytes();

                Post post = new Post(senderId, msg, timeStamp);
                System.out.println(post);
                boolean matches = false;
                try (ObjectInputStream o = new ObjectInputStream(new FileInputStream("./" + senderId + ".pub"))) {
                    Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
                    verificationAlgorithm.initVerify((PublicKey) o.readObject());
                    verificationAlgorithm.update(senderId.getBytes());
                    verificationAlgorithm.update(msg.getBytes());
                    verificationAlgorithm.update(timeStamp.getBytes());
                    matches = verificationAlgorithm.verify(sign);
                } catch (Exception e) {
                    System.out.println(e);
                }
                System.out.println("signature matches: " + matches);

                if (matches) {
                    posts.add(post);
                }
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}

public class Server {
    public static final HashMap<String, Boolean> users = new HashMap<>();

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Invalid arguments");
            return;
        }

        List<Post> posts = new ArrayList<>();
        try (ServerSocket ssocket = new ServerSocket(Integer.parseInt(args[0]))) {
            while (true) {
                Socket s = ssocket.accept();
                Thread t = new Thread(new ServerClient(s, posts));
                t.start();
            }
        }
    }
}
