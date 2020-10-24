import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class MiniSSLServer {

	protected static char[] PASSWORD = "minissl".toCharArray();

	public static void main(String[] args) throws Exception {
		boolean tls13 = args.length == 2;
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(MiniSSLServer.class.getResourceAsStream("/minissl.ks"), PASSWORD);
		kmf.init(ks, PASSWORD);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(kmf.getKeyManagers(), null, null);
		SSLServerSocket ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(Integer.parseInt(args[0]));
		ss.setEnabledProtocols(new String[] {tls13 ? "TLSv1.3" : "TLSv1.2"});
		// only use cipher suites supported by Google Chrome
		String[] cipherSuites = new String[] {
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
				//"TLS_RSA_WITH_AES_128_CBC_SHA",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				//"TLS_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				//"TLS_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
				//"TLS_RSA_WITH_AES_256_CBC_SHA"
		};
		for (String suite : cipherSuites) {
			System.out.println(suite);
			for (int i = 0; i < 5; i++) {
				if (!tls13)
					ss.setEnabledCipherSuites(new String[] { suite });
				Socket s = ss.accept();
				try {
					BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
					String line;
					while ((line = br.readLine()) != null) {
						if (line.length() == 0)
							break;
					}
					s.getOutputStream().write("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello SSL!\r\n".getBytes("ISO-8859-1"));
					System.out.println("\tOK");
				} catch (IOException ex) {
					System.out.println("\tError: " + ex.toString());
				} finally {
					s.close();
				}
			}
		}
		ss.close();
	}
}
