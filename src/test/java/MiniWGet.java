import java.io.InputStream;
import java.net.URL;

public class MiniWGet {

	public static void main(String[] args) throws Exception {
		InputStream in = new URL(args[0]).openStream();
		try {
			byte[] buffer = new byte[4096];
			while (in.read(buffer) != -1)
				;
		} finally {
			in.close();
		}
	}
}
