package net.sf.jsslkeylog;

import java.lang.classfile.CodeBuilder;
import java.lang.constant.ClassDesc;
import java.lang.constant.ConstantDescs;
import java.lang.constant.MethodTypeDesc;

/**
 * Transformer to transform <tt>RSAClientKeyExchange</tt> and
 * <tt>PreMasterSecret</tt> classes to log <tt>RSA</tt> values.
 */
public class RSAClientKeyExchangeTransformer extends AbstractTransformer {

	public RSAClientKeyExchangeTransformer(String className) {
		super(className, "<init>");
	}

	@Override
	protected void visitEndOfMethod(CodeBuilder builder, MethodTypeDesc desc) {
		if (!desc.descriptorString().contains("Ljava/security/PublicKey;") && !desc.descriptorString().contains("Ljava/security/PrivateKey;"))
			return;
		final String preMasterType = "Ljavax/crypto/SecretKey;";
		builder.aload(0);
		builder.getfield(ClassDesc.ofInternalName(className), "encrypted", ConstantDescs.CD_byte.arrayType());
		builder.aload(2);
		builder.getfield(ClassDesc.ofInternalName("sun/security/ssl/RSAKeyExchange$RSAPremasterSecret"), "premasterSecret", ClassDesc.ofDescriptor(preMasterType));
		builder.invokestatic(ClassDesc.ofInternalName(className), "$LogWriter$logRSA", MethodTypeDesc.of(ConstantDescs.CD_void, ConstantDescs.CD_byte.arrayType(), ClassDesc.ofDescriptor(preMasterType)), false);
	}
}
