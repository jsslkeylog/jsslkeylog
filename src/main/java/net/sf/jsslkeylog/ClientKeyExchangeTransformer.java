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
		super(className, null);
		System.out.println("---> "+className);
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
					
					mv.visitVarInsn(ALOAD, handshakeContextVar);
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "clientHelloRandom", "Lsun/security/ssl/RandomCookie;");
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/RandomCookie", "randomBytes", "[B");
					mv.visitVarInsn(ALOAD, lastAloadVar);
					mv.visitVarInsn(ALOAD, handshakeContextVar);
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/HandshakeContext", "conContext", "Lsun/security/ssl/TransportContext;");
					mv.visitFieldInsn(GETFIELD, "sun/security/ssl/TransportContext", "transport", "Lsun/security/ssl/SSLTransport;");
					mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logClientRandom", "([BLjavax/crypto/SecretKey;Ljava/lang/Object;)V", false);

					System.out.println("\tFOUND IT!");
					lastAloadVar = handshakeContextVar = -1;
				}
			};
		}
		return mv;
	}

	@Override
	protected void visitEndOfMethod(MethodVisitor mv, String desc) {
		final String packageName = "sun/security/ssl";
		final String masterSecretType = "Ljavax/crypto/SecretKey;";
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "clnt_random", "L" + packageName + "/RandomCookie;");
		mv.visitFieldInsn(GETFIELD, packageName + "/RandomCookie", "random_bytes", "[B");
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "session", "L" + packageName + "/SSLSessionImpl;");
		mv.visitMethodInsn(INVOKEVIRTUAL, packageName + "/SSLSessionImpl", "getMasterSecret", "()" + masterSecretType, false);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, "conn", "L" + packageName + "/SSLSocketImpl;");
		mv.visitMethodInsn(INVOKESTATIC, className, "$LogWriter$logClientRandom", "([B" + masterSecretType + "Ljavax/net/ssl/SSLSocket;)V", false);
	}
}
