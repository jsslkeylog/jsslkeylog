package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

/**
 * Transformer to transform <tt>RSAClientKeyExchange</tt> and
 * <tt>PreMasterSecret</tt> classes to log <tt>RSA</tt> values.
 */
public class RSAClientKeyExchangeTransformer extends AbstractTransformer {

	public RSAClientKeyExchangeTransformer(String className) {
		super(className, "<init>", 2);
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		if (!desc.contains("Ljava/security/PublicKey;") && !desc.contains("Ljava/security/PrivateKey;"))
			return;
		final String preMasterType = "Ljavax/crypto/SecretKey;";
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "encrypted", "[B");
		if (className.endsWith("Exchange$RSAClientKeyExchangeMessage")) {
			mv.visitVarInsn(ALOAD, 2);
			mv.visitFieldInsn(GETFIELD, "sun/security/ssl/RSAKeyExchange$RSAPremasterSecret", "premasterSecret", preMasterType);
		} else {
			mv.visitVarInsn(ALOAD, 0);
			mv.visitFieldInsn(GETFIELD, className, "preMaster", preMasterType);
		}
		mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logRSA", "([B" + preMasterType + ")V", false);
	}
}
