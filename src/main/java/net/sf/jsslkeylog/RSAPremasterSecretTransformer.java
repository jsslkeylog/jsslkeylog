package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

/**
 * Transformer to transform <tt>RSAPremasterSecret</tt> classes to log
 * <tt>RSA</tt> values on the server.
 */
public class RSAPremasterSecretTransformer extends AbstractTransformer {

	public RSAPremasterSecretTransformer(String className) {
		super(className, "decode", 3);
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 2);
		mv.visitInsn(SWAP);
		mv.visitFieldInsn(GETFIELD, "sun/security/ssl/RSAKeyExchange$RSAPremasterSecret", "premasterSecret", "Ljavax/crypto/SecretKey;");
		mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logRSA", "([BLjavax/crypto/SecretKey;)V", false);
	}
}
