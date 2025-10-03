package net.sf.jsslkeylog;

import java.lang.classfile.ClassBuilder;
import java.lang.classfile.ClassElement;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.CodeElement;
import java.lang.classfile.CodeTransform;
import java.lang.classfile.MethodModel;
import java.lang.classfile.MethodTransform;
import java.lang.classfile.Opcode;
import java.lang.classfile.constantpool.Utf8Entry;
import java.lang.classfile.instruction.FieldInstruction;
import java.lang.classfile.instruction.InvokeInstruction;
import java.lang.classfile.instruction.LineNumber;
import java.lang.classfile.instruction.LoadInstruction;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;

/**
 * Transformer to transform
 * <tt>ClientKeyExchangeConsumer/ClientKeyExchangeProducer</tt> classes to log
 * <tt>CLIENT_RANDOM</tt> values.
 */
public class ClientKeyExchangeTransformer extends AbstractTransformer {

	public ClientKeyExchangeTransformer(String className) {
		super(className, null);
	}

	@Override
	public void accept(ClassBuilder builder, ClassElement element) {
		if (element instanceof MethodModel mm && (mm.methodName().equalsString("consume") || mm.methodName().equalsString("produce"))) {
			builder.transformMethod(mm, MethodTransform.transformingCode(CodeTransform.ofStateful(()-> new CodeTransform() {
				private int lastAloadVar = -1;
				private int handshakeContextVar = -1;

				@Override
				public void accept(CodeBuilder builder, CodeElement element) {
					if (element instanceof FieldInstruction fi && fi.opcode().equals(Opcode.GETFIELD) && fi.name().equalsString("handshakeSession") && fi.owner().asInternalName().matches("sun/security/ssl/(Client|Server)HandshakeContext") && fi.type().equalsString("Lsun/security/ssl/SSLSessionImpl;")) {
						handshakeContextVar = lastAloadVar;
						lastAloadVar = -1;
					} else if (element instanceof LoadInstruction li) {
						lastAloadVar = li.slot();
					} else if (element instanceof InvokeInstruction ii && ii.opcode().equals(Opcode.INVOKEVIRTUAL) && ii.owner().name().equalsString("sun/security/ssl/SSLSessionImpl") && ii.type().equalsString("(Ljavax/crypto/SecretKey;)V") && !ii.isInterface()) {
						if (lastAloadVar == -1 || handshakeContextVar == -1) throw new IllegalStateException();
						int masterSecretVar = lastAloadVar;
						builder.with(element);
						builder.aload(handshakeContextVar);
						builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "handshakeSession", ClassDesc.ofDescriptor("Lsun/security/ssl/SSLSessionImpl;"));
						builder.aload(masterSecretVar);
						builder.invokestatic(ClassDesc.ofInternalName(className), "$LogWriter$logSessionKey", MethodTypeDesc.ofDescriptor("(Ljavax/net/ssl/SSLSession;Ljavax/crypto/SecretKey;)V"), false);
						builder.aload(handshakeContextVar);
						builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "clientHelloRandom", ClassDesc.ofDescriptor("Lsun/security/ssl/RandomCookie;"));
						builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/RandomCookie"), "randomBytes", ClassDesc.ofDescriptor("[B"));
						builder.aload(masterSecretVar);
						builder.aload(handshakeContextVar);
						builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "conContext", ClassDesc.ofDescriptor("Lsun/security/ssl/TransportContext;"));
						builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/TransportContext"), "transport", ClassDesc.ofDescriptor("Lsun/security/ssl/SSLTransport;"));
						builder.invokestatic(ClassDesc.ofInternalName(className), "$LogWriter$logClientRandom", MethodTypeDesc.ofDescriptor("([BLjavax/crypto/SecretKey;Ljava/lang/Object;)V"), false);
						lastAloadVar = handshakeContextVar = -1;
						return;
					} else if (!(element instanceof LineNumber)) {
						lastAloadVar = -1;
					}
					builder.with(element);
				}
			})));
		} else {
			builder.with(element);
		}
	}

	@Override
	protected void visitEndOfMethod(CodeBuilder builder, MethodTypeDesc desc) {
		throw new IllegalStateException();
	}
}
