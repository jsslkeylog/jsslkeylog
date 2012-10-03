package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

/**
 * Transformer to transform <tt>RSAClientKeyExchange</tt> and
 * <tt>PreMasterSecret</tt> classes to log <tt>RSA</tt> values.
 */
public class RSAClientKeyExchangeTransformer extends AbstractTransformer {

	public RSAClientKeyExchangeTransformer(String className) {
		super(className, "<init>");
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		String preMasterType = "Ljavax/crypto/SecretKey;";
		if (className.endsWith("/PreMasterSecret")) {
			preMasterType = "[B";
		}
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "encrypted", "[B");
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "preMaster", preMasterType);
		mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logRSA", "([B" + preMasterType + ")V");
	}
}
