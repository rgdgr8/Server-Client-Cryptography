import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;

public class Client {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Invalid arguments");
            return;
        }

        String host = args[0];// hostname of server
        int port = Integer.parseInt(args[1]);// port number of server
        String clientId = args[2];// client Id to uniquely identify this client

        try (Socket s = new Socket(host, port);
                DataOutputStream dout = new DataOutputStream(s.getOutputStream());
                DataInputStream din = new DataInputStream(s.getInputStream())) {

            int size = din.readInt();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            System.out.println("There are " + size + " post(s)\n");
            for (int i = 0; i < size; i++) {
                String sender = din.readUTF();
                byte[] msg = Base64.getDecoder().decode(din.readUTF().getBytes());
                String timeStamp = din.readUTF();

                System.out.println("Sender: " + sender);
                System.out.println("Time: " + timeStamp);
                try (ObjectInputStream o = new ObjectInputStream(new FileInputStream("./" + clientId + ".prv"))) {
                    cipher.init(Cipher.DECRYPT_MODE, (Key) o.readObject());// decryption using the pvt key of recvr
                    byte[] plainText = cipher.doFinal(msg);
                    System.out.println(new String(plainText));
                } catch (Exception e) {
                    //System.out.println(e);

                    System.out.println(new String(msg));
                }
                System.out.println("\n");
            }

            BufferedReader scanner = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Do you want to add a post? [1/0]");
            int inp = Integer.parseInt(scanner.readLine());
            if (inp != 1) {
                dout.writeBoolean(false);
                return;
            }

            dout.writeBoolean(true);
            dout.writeUTF(clientId);
            System.out.println("Enter the recipient userid (type 'all' for posting without encryption):");
            String recvrId = scanner.readLine();
            dout.writeUTF(recvrId);
            if(!din.readBoolean())// if verification fails
                return;

            System.out.println("Enter your message:");
            byte[] msg = scanner.readLine().getBytes();
            if (!recvrId.equals("all")) {
                try (ObjectInputStream o = new ObjectInputStream(new FileInputStream("./" + recvrId + ".pub"))) {
                    cipher.init(Cipher.ENCRYPT_MODE, (Key) o.readObject());// encryption using the pub key of recvr
                    msg = cipher.doFinal(msg);
                }
            }
            String mString = Base64.getEncoder().encodeToString(msg);
            //System.out.println(mString.length());
            dout.writeUTF(mString);

            DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
            String timeStamp = dateFormat.format(new Date());
            dout.writeUTF(timeStamp);

            try (ObjectInputStream o = new ObjectInputStream(new FileInputStream("./" + clientId + ".prv"))) {
                Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
                signatureAlgorithm.initSign((PrivateKey) o.readObject());
                signatureAlgorithm.update(clientId.getBytes());
                signatureAlgorithm.update(mString.getBytes());
                signatureAlgorithm.update(timeStamp.getBytes());
                byte[] signature = signatureAlgorithm.sign();
                dout.write(signature);
            }
        }
    }
}
