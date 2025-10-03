package net.sf.jsslkeylog;

import java.lang.classfile.CodeBuilder;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;

/**
 * Transformer to transform <tt>RSAPremasterSecret</tt> classes to log
 * <tt>RSA</tt> values on the server.
 */
public class RSAPremasterSecretTransformer extends AbstractTransformer {

	public RSAPremasterSecretTransformer(String className) {
		super(className, "decode");
	}

	@Override
	protected void visitEndOfMethod(CodeBuilder builder, MethodTypeDesc desc) {
		builder.dup();
		builder.aload(2);
		builder.swap();
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/RSAKeyExchange$RSAPremasterSecret"), "premasterSecret", ClassDesc.ofDescriptor("Ljavax/crypto/SecretKey;"));
		builder.invokestatic(ClassDesc.ofInternalName(className), "$LogWriter$logRSA", MethodTypeDesc.ofDescriptor("([BLjavax/crypto/SecretKey;)V"), false);
	}
}
