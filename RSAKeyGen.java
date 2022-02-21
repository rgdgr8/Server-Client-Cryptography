/* This program generates a pair of matching public/private RSA keys.
 * It takes a userid as an argument, and places the generated keys in
 * "<userid>.pub" and "<userid>.prv" in the current working directory.
 * It is up to you to put the generated keys at some appropriate
 * location for the client/server programs to use.
 *
 * DO NOT use or somehow invoke the code here from inside your client/
 * server to generate new keys.
 */

import java.io.*;
import java.security.*;

public class RSAKeyGen {

	public static void generateKeys(String [] args) throws Exception {

		if (args.length != 1) {
			return;
		}

		File fpub = new File(args[0]+".pub");
		File fpvr = new File(args[0]+".prv");
		// if(fpub.exists() && fpvr.exists()){
		// 	return;
		// }

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.genKeyPair();

		ObjectOutputStream objOut = new ObjectOutputStream(new FileOutputStream(fpub));
		objOut.writeObject(kp.getPublic());
		objOut.close();

		objOut = new ObjectOutputStream(new FileOutputStream(fpvr));
		objOut.writeObject(kp.getPrivate());

	}

}
