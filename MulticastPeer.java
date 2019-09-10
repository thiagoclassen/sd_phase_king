import java.net.*;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;
import java.util.Base64.Encoder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.lang.management.ManagementFactory;

public class MulticastPeer {

	private static final String group_ip = "228.5.6.7";
	private static MulticastSocket s = null;
	private static Scanner scanner = null;
	private static InetAddress group = null;
	private static Keys myKeys = new Keys();
	private static String myId;

	public static void main(String args[]) {

		try {

			myId = ManagementFactory.getRuntimeMXBean().getName();
			group = InetAddress.getByName(group_ip);
			s = new MulticastSocket(6789);
			s.joinGroup(group);

			myKeys.keys();

			Receiver receiver = new Receiver(s, myKeys);
			String message = new String("");

			System.out.println("Waiting for all 4 proccess:");

			do {

				Thread.sleep(3000);
				sendKey();

			} while (3 == 4);

			System.out.println("Type your message:");

			do {
				scanner = new Scanner(System.in);
				message = scanner.nextLine();
				byte[] m = (myId + "#:#" + message).getBytes();
				DatagramPacket messageOut = new DatagramPacket(m, m.length, group, 6789);
				s.send(messageOut);
				// sendKey();

			} while (message.compareTo("quit") != 0);

			s.leaveGroup(group);
			receiver.stop();

		} catch (SocketException e) {
			System.out.println("Socket: " + e.getMessage());
		} catch (IOException e) {
			System.out.println("IO: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (s != null)
				s.close();
			if (scanner != null)
				scanner.close();
		}
	}

	private static void sendKey() throws IOException {
		String message = "pubKey#:#" + myId + "#:#" + myKeys.getMyPublicKey().toString();
		byte[] m = message.getBytes();
		DatagramPacket messageOut = new DatagramPacket(m, m.length, group, 6789);
		s.send(messageOut);
	}

}

class Receiver extends Thread {

	private MulticastSocket socket;
	private static Keys myKeys;

	public Receiver(MulticastSocket s, Keys keyChain) {
		this.myKeys = keyChain;
		this.socket = s;
		this.start();
	}

	public void run() {
		try {
			String message = new String("");
			String[] values;

			do {
				byte[] buffer = new byte[1000];
				DatagramPacket messageIn = new DatagramPacket(buffer, buffer.length);
				this.socket.receive(messageIn);
				message = new String(messageIn.getData());
				values = message.split("#:#");

				System.out.println("Received:" + message);

				switch (values[0]) {
				case "pubKey":
					myKeys.addKeyChain(values[1], values[2]);
				}

			} while (message.compareTo("Quit") != 0);

		} catch (IOException e) {
			System.out.println("IO: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}

class Keys {

	private static Map<String, PublicKey> keyChain;
	private static KeyPair pair;
	private static String myPrivKey;
	private static String myPublicKey;

	public void keys() throws NoSuchAlgorithmException {

		// Creating KeyPair generator object
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		Encoder encoder = Base64.getEncoder();

		// Initializing the KeyPairGenerator
		keyPairGen.initialize(2048);

		// Generating the pair of keys
		pair = keyPairGen.generateKeyPair();

		// Getting the private key from the key pair
		myPrivKey = encoder.encodeToString(pair.getPrivate().getEncoded());

		// Getting the public key from the key pair
		myPublicKey = encoder.encodeToString(pair.getPublic().getEncoded());
		System.out.println((myPublicKey));

	}

	public String getMyPrivateKey() {
		return myPrivKey;
	}

	public String getMyPublicKey() {
		return myPublicKey;
	}

	public int getKeyChainSize() {
		return keyChain.size();
	}

	public void addKeyChain(String id, String pKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		//String pubKeyPEM = pKey.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----", "");
		byte[] encodedPublicKey = Base64.getDecoder().decode(pKey);
		
		KeyFactory kf = KeyFactory.getInstance("RSA");

		X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedPublicKey);
		System.out.println(kf.generatePublic(spec));

		keyChain.put(id, kf.generatePublic(spec));
	}

	public void removeKeyChain(String id, PublicKey pKey) {
		keyChain.remove(id);
	}
}
