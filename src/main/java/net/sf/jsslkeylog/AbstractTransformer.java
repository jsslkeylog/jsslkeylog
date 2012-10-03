package net.sf.jsslkeylog;

import static org.objectweb.asm.Opcodes.*;

import java.io.IOException;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

/**
 * Abstract base class of all transformer classes.
 */
public abstract class AbstractTransformer extends ClassVisitor {

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
		super(ASM4);
		this.className = className;
		this.methodName = methodName;
	}

	/**
	 * Set the next visitor for this {@link ClassVisitor}.
	 */
	public void setNextVisitor(ClassVisitor cv) {
		this.cv = cv;
	}

	@Override
	public MethodVisitor visitMethod(int access, String name, final String desc, String signature, String[] exceptions) {
		MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
		if (name.equals(methodName)) {
			return new MethodVisitor(ASM4, mv) {
				@Override
				public void visitInsn(int opcode) {
					if (opcode == RETURN) {
						visitEndOfMethod(mv, desc);
					}
					super.visitInsn(opcode);
				}
			};
		}
		return mv;
	}

	/**
	 * Called to append bytecodes at the end of the method (before every
	 * {@link org.objectweb.asm.Opcodes#RETURN} instruction.
	 * 
	 * @param mv
	 *            MethodVisitor of the current method
	 * @param desc
	 *            Method signature
	 */
	protected abstract void visitEndOfMethod(MethodVisitor mv, String desc);

	@Override
	public void visitEnd() {
		copyLogMethods();
		super.visitEnd();
	}

	/**
	 * Copy methods from the {@link LogWriter} class into the currently
	 * instrumented class.
	 */
	private void copyLogMethods() {
		try {
			ClassReader cr = new ClassReader(LogWriter.class.getResourceAsStream("/" + LogWriter.class.getName().replace('.', '/') + ".class"));
			cr.accept(new ClassVisitor(ASM4) {
				@Override
				public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
					return new MethodVisitor(ASM4, AbstractTransformer.this.visitMethod(access, "$LogWriter$" + name, desc, signature, exceptions)) {
						@Override
						public void visitMethodInsn(int opcode, String owner, String name, String desc) {
							if (owner.equals(LogWriter.class.getName().replace('.', '/'))) {
								owner = className;
								name = "$LogWriter$" + name;
							}
							super.visitMethodInsn(opcode, owner, name, desc);
						}
					};
				}
			}, 0);
		} catch (IOException ex) {
			throw new RuntimeException("Unable to copy log methods", ex);
		}
	}
}