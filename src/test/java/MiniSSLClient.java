import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class MiniSSLClient {

	public static void main(String[] args) throws Exception {
		boolean tls13 = args.length == 3;
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(MiniSSLServer.class.getResourceAsStream("/minissl.ks"), MiniSSLServer.PASSWORD);
		tmf.init(ks);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, new TrustManager[] { new X509TrustManager() {
			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
			@Override
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}
			@Override
			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}
		} }, null);
		SSLSocketFactory ssf = ctx.getSocketFactory();
		while (true) {
			SSLSocket s;
			try {
				s = (SSLSocket) ssf.createSocket(args[0], Integer.parseInt(args[1]));
			} catch (ConnectException ex) {
				return;
			}
			try {
				if (tls13) {
					s.setEnabledProtocols(new String[] {"TLSv1.3"});
				} else {
					s.setEnabledProtocols(new String[] {"TLSv1.2"});
					s.setEnabledCipherSuites(s.getSupportedCipherSuites());
				}
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
