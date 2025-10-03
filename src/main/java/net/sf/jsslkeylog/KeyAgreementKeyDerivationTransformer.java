package net.sf.jsslkeylog;

import java.lang.classfile.CodeBuilder;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;

/**
 * Transformer to transform <tt>*KAKeyDerivation</tt> classes to log
 * TLSv1.3 values.
 */
public class KeyAgreementKeyDerivationTransformer extends AbstractTransformer {

	public KeyAgreementKeyDerivationTransformer(String className) {
		super(className, "t13DeriveKey");
	}

	@Override
	protected void visitEndOfMethod(CodeBuilder builder, MethodTypeDesc desc) {
		builder.dup();
		builder.aconst_null();
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "localPrivateKey", ClassDesc.ofDescriptor("Ljava/security/PrivateKey;"));
		builder.aload(1);
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "context", ClassDesc.ofDescriptor("Lsun/security/ssl/HandshakeContext;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "clientHelloRandom", ClassDesc.ofDescriptor("Lsun/security/ssl/RandomCookie;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/RandomCookie"), "randomBytes", ClassDesc.ofDescriptor("[B"));
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "context", ClassDesc.ofDescriptor("Lsun/security/ssl/HandshakeContext;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "conContext", ClassDesc.ofDescriptor("Lsun/security/ssl/TransportContext;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/TransportContext"), "transport", ClassDesc.ofDescriptor("Lsun/security/ssl/SSLTransport;"));
		builder.invokestatic(ClassDesc.ofInternalName(className), "$LogWriter$logTLS13KeyAgreement", MethodTypeDesc.ofDescriptor("(Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;Ljava/security/PrivateKey;Ljava/lang/String;[BLjava/lang/Object;)V"), false);
	}
}
