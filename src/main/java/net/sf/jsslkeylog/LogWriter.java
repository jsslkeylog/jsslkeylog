package net.sf.jsslkeylog;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Utility class that contains methods for writing to the logfile. Note that
 * these methods get copied into instrumented classes; therefore, they should
 * not refer to fields or other non-API classes.
 */
public class LogWriter {

	public static final String LOGFILE_PROPERTY_NAME = "net.sf.jsslkeylog.logfilename";
	public static final String VERBOSE_PROPERTY_NAME = "net.sf.jsslkeylog.verbose";
	public static final String TLS13_DEBUG_PROPERTY_NAME = "net.sf.jsslkeylog.tls13.debug";

	public static void logRSA(byte[] encryptedPreMasterSecret, SecretKey preMasterSecret) {
		logLine("RSA " + hex(encryptedPreMasterSecret).substring(0, 16) + " " + hex(preMasterSecret.getEncoded()), null);
	}

	public static void logClientRandom(byte[] clientRandom, SecretKey masterSecret, Object maybeConn) {
		logClientRandom(clientRandom, masterSecret, maybeConn instanceof SSLSocket ? (SSLSocket) maybeConn : null);
	}
	
	public static void logClientRandom(byte[] clientRandom, SecretKey masterSecret, SSLSocket conn) {
		logLine("CLIENT_RANDOM " + hex(clientRandom) + " " + hex(masterSecret.getEncoded()),
				conn == null ? null : conn.getLocalSocketAddress() + " -> " + conn.getRemoteSocketAddress());
	}

	/**
	 * RSA Session-ID:4b8569d40aac2dba1fb8e1ad5260f1b310bd050515f3f14b59cf1bcc05e29bed
	 * Master-Key
	 * :6fd5bf0156d037cc7091bcd9c91b4d82ced2d78e4d76569d9b5b15f34c98c598d00ce80dd7b758094fded82ac166b9c8
	 * @param session
	 * @param masterSecret
	 */
	public static void logSessionKey(SSLSession session, SecretKey masterSecret) {
		logLine("RSA Session-ID:" + hex(session.getId()) + " Master-Key:" + hex(masterSecret.getEncoded()), null);
	}


	public static void logTLS13KeyAgreement(SecretKey resultSecret, SecretKey inputSecret, PrivateKey inputPrivate, String algorithm, byte[] clientRandom, Object maybeConn) {
		if (inputSecret != null) {
			String logName = null;
			switch(algorithm) {
			case "TlsClientHandshakeTrafficSecret": logName="CLIENT_HANDSHAKE_TRAFFIC_SECRET"; break;
			case "TlsServerHandshakeTrafficSecret": logName="SERVER_HANDSHAKE_TRAFFIC_SECRET"; break;
			case "TlsClientAppTrafficSecret": logName="CLIENT_TRAFFIC_SECRET_0"; break;
			case "TlsServerAppTrafficSecret": logName="SERVER_TRAFFIC_SECRET_0"; break;
			}
			if (logName != null) {
				logLine(logName+" " + hex(clientRandom) + " " + hex(resultSecret.getEncoded()), 
						maybeConn instanceof SSLSocket ? (((SSLSocket) maybeConn).getLocalSocketAddress() + "->" + ((SSLSocket) maybeConn).getRemoteSocketAddress()) : null);
			}
		}
		if (Boolean.getBoolean(TLS13_DEBUG_PROPERTY_NAME)) {
			String inputKey = inputSecret == null ? "PRIVKEY "+hex(inputPrivate.getEncoded()) : "SECKEY "+hex(inputSecret.getEncoded());
			logLine("TLS13_DEBUG " + algorithm + " " + hex(clientRandom) + " " + hex(resultSecret.getEncoded())+" "+inputKey, 
					maybeConn instanceof SSLSocket ? (((SSLSocket) maybeConn).getLocalSocketAddress() + "->" + ((SSLSocket) maybeConn).getRemoteSocketAddress()) : null);
		}
	}

	private static String hex(byte[] encoded) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < encoded.length; i++) {
			int b = encoded[i] & 0xFF;
			sb.append(b < 0x10 ? "0" : "").append(Integer.toHexString(b));
		}
		return sb.toString();
	}

	public static void logLine(String line, String debugInfo) {
		String logfile = System.getProperty(LOGFILE_PROPERTY_NAME);
		// yes, I know, bad idea to synchonize on a String value, but since
		// this method gets copied into other classes (in different class
		// loaders) via instrumentation, I don't have any other "global"
		// object available to synchronize against.
		synchronized (logfile) {
			try {
				FileOutputStream fos = new FileOutputStream(logfile, true);
				try {
					if (Boolean.getBoolean(VERBOSE_PROPERTY_NAME)) {
						String debugLog = "## " +
								new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()) +
								(debugInfo == null ? "" : ": " + debugInfo) + "\r\n";
						fos.write(debugLog.getBytes("ISO-8859-1"));
					}
					fos.write((line + "\r\n").getBytes("ISO-8859-1"));
				} finally {
					fos.close();
				}
			} catch (IOException ex) {
				InternalError t = new InternalError("Unable to log SSL Key Log");
				t.initCause(ex);
				throw t;
			}
		}
	}
}
