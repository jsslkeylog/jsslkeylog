package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

/**
 * Transformer to transform
 * <tt>ClientKeyExchangeConsumer/ClientKeyExchangeProducer</tt> classes to log
 * <tt>CLIENT_RANDOM</tt> values.
 */
public class ClientKeyExchangeTransformer extends AbstractTransformer {

	public ClientKeyExchangeTransformer(String className) {
		super(className, null, 0);
	}

	@Override
	public MethodVisitor visitMethod(int access, String name, final String desc, String signature, String[] exceptions) {
		MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
		if (name.equals("consume") || name.equals("produce")) {
			return new MethodVisitor(API, mv) {

				int lastAloadVar = -1;
				int handshakeContextVar = -1;

				@Override
				public void visitInsn(int opcode) {
					super.visitInsn(opcode);
					lastAloadVar = -1;
				}
				
				@Override
				public void visitVarInsn(int opcode, int var) {
					super.visitVarInsn(opcode, var);
					lastAloadVar = opcode == ALOAD ? var : -1;
				}

				@Override
				public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
					super.visitFieldInsn(opcode, owner, name, descriptor);
					if (opcode == GETFIELD && name.equals("handshakeSession") && owner.matches("sun/security/ssl/(Client|Server)HandshakeContext") && descriptor.equals("Lsun/security/ssl/SSLSessionImpl;"))
						handshakeContextVar = lastAloadVar;
					lastAloadVar = -1;
				}

				@Override
				public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
					super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
					if (opcode != INVOKEVIRTUAL || !owner.equals("sun/security/ssl/SSLSessionImpl") || !name.equals("setMasterSecret") || !descriptor.equals("(Ljavax/crypto/SecretKey;)V") || isInterface) {
						lastAloadVar = -1;
						return;
					}
					if (lastAloadVar == -1 || handshakeContextVar == -1) throw new IllegalStateException();

					int masterSecretVar = lastAloadVar;

					mv.visitVarInsn(ALOAD, handshakeContextVar);
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "handshakeSession", "Lsun/security/ssl/SSLSessionImpl;");
					mv.visitVarInsn(ALOAD, masterSecretVar);
					mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logSessionKey", "(Ljavax/net/ssl/SSLSession;Ljavax/crypto/SecretKey;)V", false);

					mv.visitVarInsn(ALOAD, handshakeContextVar);
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "clientHelloRandom", "Lsun/security/ssl/RandomCookie;");
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/RandomCookie", "randomBytes", "[B");
					mv.visitVarInsn(ALOAD, masterSecretVar);
					mv.visitVarInsn(ALOAD, handshakeContextVar);
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "conContext", "Lsun/security/ssl/TransportContext;");
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/TransportContext", "transport", "Lsun/security/ssl/SSLTransport;");
					mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logClientRandom", "([BLjavax/crypto/SecretKey;Ljava/lang/Object;)V", false);

					lastAloadVar = handshakeContextVar = -1;
				}
			};
		}
		return mv;
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		throw new IllegalStateException();
	}
}
