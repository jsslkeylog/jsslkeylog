package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

/**
 * Transformer to transform <tt>SSLSecretDerivation</tt> classes to log
 * TLSv1.3 values.
 */
public class SecretDerivationTransformer extends AbstractTransformer {

	public SecretDerivationTransformer(String className) {
		super(className, "deriveKey", 7);
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "secret", "Ljavax/crypto/SecretKey;"); 
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "context", "Lsun/security/ssl/HandshakeContext;");
		mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "clientHelloRandom", "Lsun/security/ssl/RandomCookie;");
		mv.visitFieldInsn(GETFIELD, "sun/security/ssl/RandomCookie", "randomBytes", "[B");
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "context", "Lsun/security/ssl/HandshakeContext;");
		mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "conContext", "Lsun/security/ssl/TransportContext;");
		mv.visitFieldInsn(GETFIELD, "sun/security/ssl/TransportContext", "transport", "Lsun/security/ssl/SSLTransport;");
		mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logTLS13KeyAgreement", "(Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;Ljava/security/PrivateKey;Ljava/lang/String;[BLjava/lang/Object;)V", false);
	}
}
