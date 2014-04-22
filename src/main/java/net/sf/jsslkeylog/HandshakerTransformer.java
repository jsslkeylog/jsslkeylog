package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

/**
 * Transformer to transform <tt>Handshaker</tt> classes to log
 * <tt>CLIENT_RANDOM</tt> values.
 */
public class HandshakerTransformer extends AbstractTransformer {

	public HandshakerTransformer(String className) {
		super(className, "calculateKeys");
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		String packageName = className.replace("/Handshaker", "");
		String masterSecretType = "Ljavax/crypto/SecretKey;";
		if (desc.equals("([B)V")) {
			masterSecretType = "[B";
		}
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "clnt_random", "L" + packageName + "/RandomCookie;");
		mv.visitFieldInsn(GETFIELD, packageName + "/RandomCookie", "random_bytes", "[B");
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "session", "L" + packageName + "/SSLSessionImpl;");
		mv.visitMethodInsn(INVOKEVIRTUAL, packageName + "/SSLSessionImpl", "getMasterSecret", "()" + masterSecretType);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "conn", "L"+packageName+"/SSLSocketImpl;");
		mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logClientRandom", "([B" + masterSecretType + "Ljavax/net/ssl/SSLSocket;)V");
	}
}
