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

	protected static final int API = ASM9;
	
	protected final String className;
	private final String methodName;
	private final int methodStack;

	/**
	 * Class constructor.
	 * 
	 * @param className
	 *            Name of the class being transformed
	 * @param methodName
	 *            Name of the method(s) that should be modified
	 */
	public AbstractTransformer(String className, String methodName, int methodStack) {
		super(API);
		this.className = className;
		this.methodName = methodName;
		this.methodStack = methodStack;
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
			return new MethodVisitor(API, mv) {
				@Override
				public void visitInsn(int opcode) {
					if (opcode == RETURN || opcode == ARETURN) {
						visitEndOfMethod(mv, desc);
					}
					super.visitInsn(opcode);
				}
				
				@Override
				public void visitMaxs(int maxStack, int maxLocals) {
					if (methodStack > maxStack)
						maxStack = methodStack;
					super.visitMaxs(maxStack, maxLocals);
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
			cr.accept(new ClassVisitor(API) {
				@Override
				public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
					if (name.equals("<init>"))
						return super.visitMethod(access, name, desc, signature, exceptions);
					return new MethodVisitor(API, AbstractTransformer.this.visitMethod(access, "$LogWriter$" + name, desc, signature, exceptions)) {
						@Override
						public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
							if (owner.equals(LogWriter.class.getName().replace('.', '/'))) {
								owner = className;
								name = "$LogWriter$" + name;
							}
							super.visitMethodInsn(opcode, owner, name, desc, itf);
						}
					};
				}
			}, 0);
		} catch (IOException ex) {
			throw new RuntimeException("Unable to copy log methods", ex);
		}
	}
}