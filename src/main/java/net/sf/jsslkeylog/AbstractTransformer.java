package net.sf.jsslkeylog;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.classfile.ClassBuilder;
import java.lang.classfile.ClassElement;
import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassModel;
import java.lang.classfile.ClassTransform;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.MethodModel;
import java.lang.classfile.MethodTransform;
import java.lang.classfile.instruction.InvokeInstruction;
import java.lang.classfile.instruction.ReturnInstruction;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.net.URI;
import java.nio.file.Paths;

/**
 * Abstract base class of all transformer classes.
 */
public abstract class AbstractTransformer implements ClassTransform {

	protected final String className;
	private final String methodName;

	/**
	 * Class constructor.
	 * 
	 * @param className
	 *            Name of the class being transformed
	 * @param methodName
	 *            Name of the method(s) that should be modified
	 */
	public AbstractTransformer(String className, String methodName) {
		this.className = className;
		this.methodName = methodName;
	}

	@Override
	public void accept(ClassBuilder builder, ClassElement element) {
		if (element instanceof MethodModel mm && mm.methodName().equalsString(methodName)) {
			builder.transformMethod(mm, MethodTransform.transformingCode((b, e) -> {
				if (e instanceof ReturnInstruction) {
					visitEndOfMethod(b, mm.methodTypeSymbol());
				}
				b.with(e);
			}));
		} else {
			builder.with(element);
		}
	}

	/**
	 * Called to append bytecodes at the end of the method (before every
	 * {@link ReturnInstruction}).
	 * 
	 * @param mv
	 *            MethodVisitor of the current method
	 * @param desc
	 *            Method signature
	 */
	protected abstract void visitEndOfMethod(CodeBuilder builder, MethodTypeDesc desc);

	@Override
	public void atEnd(ClassBuilder builder) {
		copyLogMethods(builder);
	}

	/**
	 * Copy methods from the {@link LogWriter} class into the currently
	 * instrumented class.
	 */
	private void copyLogMethods(ClassBuilder builder) {
		String logWriterDesc = LogWriter.class.getName().replace('.', '/');
		ClassDesc targetClassDesc = ClassDesc.ofInternalName(className);
		ClassModel cm;
		try (InputStream in = LogWriter.class.getResourceAsStream("/" + logWriterDesc + ".class");
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			in.transferTo(baos);
			cm = ClassFile.of().parse(baos.toByteArray());
		} catch (IOException ex) {
			throw new RuntimeException("Unable to copy log methods", ex);
		}
		for (MethodModel mm : cm.methods()) {
			if (mm.methodName().equalsString("<init>")) {
				continue;
			}
			builder.withMethodBody(builder.constantPool().utf8Entry("$LogWriter$" + mm.methodName().stringValue()), mm.methodType(), mm.flags().flagsMask(),
					cb -> {
						mm.code().get().forEach(ce -> {
							if (ce instanceof InvokeInstruction ii && ii.owner().name().equalsString(logWriterDesc)) {
								cb.invoke(ii.opcode(), targetClassDesc, "$LogWriter$" + ii.name().stringValue(), ii.typeSymbol(), ii.isInterface());
							} else {
								cb.with(ce);
							}
						});
					});
		}
	}
}