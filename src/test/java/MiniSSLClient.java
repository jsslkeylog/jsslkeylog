import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class MiniSSLClient {

	public static void main(String[] args) throws Exception {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(MiniSSLServer.class.getResourceAsStream("/minissl.ks"), MiniSSLServer.PASSWORD);
		tmf.init(ks);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, tmf.getTrustManagers(), null);
		SSLSocketFactory ssf = ctx.getSocketFactory();
		while (true) {
			SSLSocket s;
			try {
				s = (SSLSocket) ssf.createSocket(args[0], Integer.parseInt(args[1]));
			} catch (ConnectException ex) {
				return;
			}
			try {
				s.setEnabledCipherSuites(s.getSupportedCipherSuites());
				s.getOutputStream().write("GET / HTTP/1.1\r\n\r\n".getBytes("ISO-8859-1"));
				BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
				while ((br.readLine()) != null)
					;
				System.out.println("\tOK");
			} finally {
				s.close();
			}
		}
	}
}
