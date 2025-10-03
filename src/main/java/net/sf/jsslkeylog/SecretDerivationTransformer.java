package net.sf.jsslkeylog;

import java.lang.classfile.ClassBuilder;
import java.lang.classfile.ClassElement;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.CodeElement;
import java.lang.classfile.CodeTransform;
import java.lang.classfile.FieldModel;
import java.lang.classfile.MethodModel;
import java.lang.classfile.MethodTransform;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;

/**
 * Transformer to transform <tt>SSLSecretDerivation</tt> classes to log
 * TLSv1.3 values.
 */
public class SecretDerivationTransformer extends AbstractTransformer {

	public SecretDerivationTransformer(String className) {
		super(className, "deriveKey");
	}

	@Override
	public void accept(ClassBuilder builder, ClassElement element) {
		if(element instanceof FieldModel fi && fi.fieldName().equalsString("secret")) {
			builder.withField("$context", ClassDesc.ofDescriptor("Lsun/security/ssl/HandshakeContext;"), 18);
			builder.with(fi);
		} else if (element instanceof MethodModel mm && mm.methodName().equalsString("<init>") && mm.methodType().equalsString("(Lsun/security/ssl/HandshakeContext;Ljavax/crypto/SecretKey;)V"))  {
			builder.transformMethod(mm, MethodTransform.transformingCode(new CodeTransform() {
				@Override
				public void atStart(CodeBuilder builder) {
					builder.aload(0);
					builder.aload(1);
					builder.putfield(ClassDesc.ofInternalName(className), "$context", ClassDesc.ofDescriptor("Lsun/security/ssl/HandshakeContext;"));
				}
				@Override
				public void accept(CodeBuilder builder, CodeElement element) {
					builder.with(element);
				}
			}));
		} else {
			super.accept(builder, element);
		}
	}

	@Override
	protected void visitEndOfMethod(CodeBuilder builder, MethodTypeDesc desc) {
		builder.dup();
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "secret", ClassDesc.ofDescriptor("Ljavax/crypto/SecretKey;")); 
		builder.aconst_null();
		builder.aload(1);
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "$context", ClassDesc.ofDescriptor("Lsun/security/ssl/HandshakeContext;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "clientHelloRandom", ClassDesc.ofDescriptor("Lsun/security/ssl/RandomCookie;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/RandomCookie"), "randomBytes", ClassDesc.ofDescriptor("[B"));
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "$context", ClassDesc.ofDescriptor("Lsun/security/ssl/HandshakeContext;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/HandshakeContext"), "conContext", ClassDesc.ofDescriptor("Lsun/security/ssl/TransportContext;"));
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/TransportContext"), "transport", ClassDesc.ofDescriptor("Lsun/security/ssl/SSLTransport;"));
		builder.invokestatic(ClassDesc.ofInternalName(className), "$LogWriter$logTLS13KeyAgreement", MethodTypeDesc.ofDescriptor("(Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;Ljava/security/PrivateKey;Ljava/lang/String;[BLjava/lang/Object;)V"), false);
	}
}
