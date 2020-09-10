import org.apache.commons.io.IOUtils;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.ClassNode;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;

import static org.objectweb.asm.Opcodes.*;

public class Main {
    public static void main(String[] args) {
        try {
            Map<String, ClassNode> classNodeMap = loadClasses(new File("lib/libksyplayer.jar"));

            Map<String, byte[]> outBytes = new HashMap<>();

            Set<Map.Entry<String, ClassNode>> entries = classNodeMap.entrySet();
            for (Map.Entry<String, ClassNode> entry : entries) {
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                String name = entry.getKey();
                //modify c.class
                if ("com/ksyun/media/player/util/c".equals(name) || "com/ksyun/media/player/misc/e".equals(name)) {// com.ksyun.media.player.util.c.class node.
                    System.err.println("skip class , name = " + name);
                } else {
                    ClassNode classNode = entry.getValue();
                    classNode.accept(cw);
                    outBytes.put(name + ".class", cw.toByteArray());
                }
            }

            outBytes.put("com/ksyun/media/player/util/c.class", dumpC());
            outBytes.put("com/ksyun/media/player/misc/e.class", dumpE());

            File file = new File("lib/libfixed.jar");
            if (file.exists())
                file.delete();
            file.createNewFile();
            saveAsJar(outBytes, "lib/libfixed.jar");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void saveAsJar(Map<String, byte[]> outBytes, String fileName) {
        try {
            // Create jar output stream
            JarOutputStream out = new JarOutputStream(new FileOutputStream(fileName));
            // For each entry in the map, save the bytes
            for (String entry : outBytes.keySet()) {
                // Appent class names to class entries
                String ext = entry.contains(".") ? "" : ".class";
                out.putNextEntry(new ZipEntry(entry + ext));
                out.write(outBytes.get(entry));
                out.closeEntry();
            }
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, ClassNode> loadClasses(File file) throws IOException {
        Map<String, ClassNode> classes = new HashMap<>();
        JarFile jarFile = new JarFile(file);
        Stream<JarEntry> stream = jarFile.stream();
        stream.forEach(new Consumer<JarEntry>() {
            @Override
            public void accept(JarEntry jarEntry) {
                readJar(jarFile, jarEntry, classes);
            }
        });
        return classes;
    }

    static Map<String, ClassNode> readJar(JarFile jar, JarEntry entry, Map<String, ClassNode> classes) {
        String name = entry.getName();
        try (InputStream jis = jar.getInputStream(entry)) {
            if (name.endsWith(".class")) {
                byte[] bytes = IOUtils.toByteArray(jis);
                String cafebabe = String.format("%02X%02X%02X%02X", bytes[0], bytes[1], bytes[2], bytes[3]);
                if (!cafebabe.toLowerCase().equals("cafebabe")) {
                    // This class doesn't have a valid magic
                    return classes;
                }
                try {
                    ClassNode cn = getNode(bytes);
                    classes.put(cn.name, cn);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return classes;
    }

    static ClassNode getNode(byte[] bytes) {
        ClassReader cr = new ClassReader(bytes);
        ClassNode cn = new ClassNode();
        try {
            cr.accept(cn, ClassReader.EXPAND_FRAMES);
        } catch (Exception e) {
            e.printStackTrace();
        }
        cr = null;
        return cn;
    }


    public static byte[] dumpC() throws Exception {

        ClassWriter cw = new ClassWriter(0);
        FieldVisitor fv;
        MethodVisitor mv;
        AnnotationVisitor av0;

        cw.visit(52, ACC_PUBLIC + ACC_SUPER, "com/ksyun/media/player/util/c", null, "java/lang/Object", null);

        cw.visitSource("c.java", null);

        {
            fv = cw.visitField(ACC_PRIVATE + ACC_FINAL + ACC_STATIC, "a", "Ljava/lang/String;", null, "ffffffffff");
            fv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(11, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLineNumber(12, l1);
            mv.visitInsn(RETURN);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/util/c;", null, l0, l2, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "a", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(15, l0);
            mv.visitLdcInsn("N/A");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE + ACC_STATIC, "f", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(19, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "b", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(23, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "a", "(Ljava/lang/String;)[Ljava/lang/Class;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(27, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Ljava/lang/String;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "c", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(31, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE + ACC_STATIC, "g", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(35, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "d", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(39, l0);
            mv.visitLdcInsn("wifi");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "b", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            Label l1 = new Label();
            Label l2 = new Label();
            mv.visitTryCatchBlock(l0, l1, l2, "java/security/NoSuchAlgorithmException");
            mv.visitLabel(l0);
            mv.visitLineNumber(45, l0);
            mv.visitLdcInsn("MD5");
            mv.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "([B)[B", false);
            mv.visitVarInsn(ASTORE, 1);
            mv.visitLabel(l1);
            mv.visitLineNumber(48, l1);
            Label l3 = new Label();
            mv.visitJumpInsn(GOTO, l3);
            mv.visitLabel(l2);
            mv.visitLineNumber(46, l2);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{"java/security/NoSuchAlgorithmException"});
            mv.visitVarInsn(ASTORE, 2);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(47, l4);
            mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
            mv.visitInsn(DUP);
            mv.visitLdcInsn("Huh, MD5 should be supported?");
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", false);
            mv.visitInsn(ATHROW);
            mv.visitLabel(l3);
            mv.visitLineNumber(50, l3);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{"[B"}, 0, null);
            mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
            mv.visitInsn(DUP);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitInsn(ARRAYLENGTH);
            mv.visitInsn(ICONST_2);
            mv.visitInsn(IMUL);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(I)V", false);
            mv.visitVarInsn(ASTORE, 2);
            Label l5 = new Label();
            mv.visitLabel(l5);
            mv.visitLineNumber(51, l5);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitVarInsn(ASTORE, 3);
            Label l6 = new Label();
            mv.visitLabel(l6);
            mv.visitLineNumber(52, l6);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitInsn(ARRAYLENGTH);
            mv.visitVarInsn(ISTORE, 4);
            Label l7 = new Label();
            mv.visitLabel(l7);
            mv.visitLineNumber(54, l7);
            mv.visitInsn(ICONST_0);
            mv.visitVarInsn(ISTORE, 5);
            Label l8 = new Label();
            mv.visitLabel(l8);
            mv.visitFrame(Opcodes.F_FULL, 6, new Object[]{"java/lang/String", "[B", "java/lang/StringBuilder", "[B", Opcodes.INTEGER, Opcodes.INTEGER}, 0, new Object[]{});
            mv.visitVarInsn(ILOAD, 5);
            mv.visitVarInsn(ILOAD, 4);
            Label l9 = new Label();
            mv.visitJumpInsn(IF_ICMPGE, l9);
            Label l10 = new Label();
            mv.visitLabel(l10);
            mv.visitLineNumber(55, l10);
            mv.visitVarInsn(ALOAD, 3);
            mv.visitVarInsn(ILOAD, 5);
            mv.visitInsn(BALOAD);
            mv.visitVarInsn(ISTORE, 6);
            Label l11 = new Label();
            mv.visitLabel(l11);
            mv.visitLineNumber(56, l11);
            mv.visitVarInsn(ILOAD, 6);
            mv.visitIntInsn(SIPUSH, 255);
            mv.visitInsn(IAND);
            mv.visitIntInsn(BIPUSH, 16);
            Label l12 = new Label();
            mv.visitJumpInsn(IF_ICMPGE, l12);
            Label l13 = new Label();
            mv.visitLabel(l13);
            mv.visitLineNumber(57, l13);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitLdcInsn("0");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitInsn(POP);
            mv.visitLabel(l12);
            mv.visitLineNumber(60, l12);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{Opcodes.INTEGER}, 0, null);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitVarInsn(ILOAD, 6);
            mv.visitIntInsn(SIPUSH, 255);
            mv.visitInsn(IAND);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toHexString", "(I)Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitInsn(POP);
            Label l14 = new Label();
            mv.visitLabel(l14);
            mv.visitLineNumber(54, l14);
            mv.visitIincInsn(5, 1);
            mv.visitJumpInsn(GOTO, l8);
            mv.visitLabel(l9);
            mv.visitLineNumber(63, l9);
            mv.visitFrame(Opcodes.F_CHOP, 2, null, 0, null);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
            mv.visitInsn(ARETURN);
            Label l15 = new Label();
            mv.visitLabel(l15);
            mv.visitLocalVariable("var1", "[B", null, l1, l2, 1);
            mv.visitLocalVariable("var7", "Ljava/security/NoSuchAlgorithmException;", null, l4, l3, 2);
            mv.visitLocalVariable("var6", "B", null, l11, l14, 6);
            mv.visitLocalVariable("var5", "I", null, l8, l9, 5);
            mv.visitLocalVariable("var0", "Ljava/lang/String;", null, l0, l15, 0);
            mv.visitLocalVariable("var1", "[B", null, l3, l15, 1);
            mv.visitLocalVariable("var2", "Ljava/lang/StringBuilder;", null, l5, l15, 2);
            mv.visitLocalVariable("var3", "[B", null, l6, l15, 3);
            mv.visitLocalVariable("var4", "I", null, l7, l15, 4);
            mv.visitMaxs(4, 7);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "e", "(Landroid/content/Context;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(67, l0);
            mv.visitLdcInsn("N/A");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE + ACC_STATIC, "a", "(Landroid/content/Context;Ljava/lang/String;)Z", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(71, l0);
            mv.visitInsn(ICONST_0);
            mv.visitInsn(IRETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("var0", "Landroid/content/Context;", null, l0, l1, 0);
            mv.visitLocalVariable("var1", "Ljava/lang/String;", null, l0, l1, 1);
            mv.visitMaxs(1, 2);
            mv.visitEnd();
        }
        cw.visitEnd();

        return cw.toByteArray();
    }

    public static byte[] dumpE() throws Exception {

        ClassWriter cw = new ClassWriter(0);
        FieldVisitor fv;
        MethodVisitor mv;
        AnnotationVisitor av0;

        cw.visit(52, ACC_PUBLIC + ACC_SUPER, "com/ksyun/media/player/misc/e", null, "java/lang/Object", null);

        cw.visitSource("e.java", null);

        cw.visitInnerClass("android/os/Build$VERSION", "android/os/Build", "VERSION", ACC_PUBLIC + ACC_STATIC);

        cw.visitInnerClass("android/provider/Settings$Secure", "android/provider/Settings", "Secure", ACC_PUBLIC + ACC_FINAL + ACC_STATIC);

        {
            fv = cw.visitField(ACC_PRIVATE + ACC_STATIC, "a", "Lcom/ksyun/media/player/misc/e;", null, null);
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE + ACC_FINAL + ACC_STATIC, "b", "Ljava/lang/String;", null, "ffffffffff");
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE, "c", "Ljava/lang/String;", null, null);
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE, "d", "Ljava/lang/String;", null, null);
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE, "e", "Ljava/lang/String;", null, null);
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE, "f", "Ljava/lang/String;", null, null);
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE, "g", "Landroid/content/Context;", null, null);
            fv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(12, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
            mv.visitInsn(RETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "a", "()Lcom/ksyun/media/player/misc/e;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            Label l1 = new Label();
            Label l2 = new Label();
            mv.visitTryCatchBlock(l0, l1, l2, null);
            Label l3 = new Label();
            mv.visitTryCatchBlock(l2, l3, l2, null);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(24, l4);
            mv.visitLdcInsn(Type.getType("Lcom/ksyun/media/player/misc/e;"));
            mv.visitInsn(DUP);
            mv.visitVarInsn(ASTORE, 0);
            mv.visitInsn(MONITORENTER);
            mv.visitLabel(l0);
            mv.visitLineNumber(26, l0);
            mv.visitFieldInsn(GETSTATIC, "com/ksyun/media/player/misc/e", "a", "Lcom/ksyun/media/player/misc/e;");
            Label l5 = new Label();
            mv.visitJumpInsn(IFNONNULL, l5);
            Label l6 = new Label();
            mv.visitLabel(l6);
            mv.visitLineNumber(27, l6);
            mv.visitTypeInsn(NEW, "com/ksyun/media/player/misc/e");
            mv.visitInsn(DUP);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "<init>", "()V", false);
            mv.visitFieldInsn(PUTSTATIC, "com/ksyun/media/player/misc/e", "a", "Lcom/ksyun/media/player/misc/e;");
            mv.visitLabel(l5);
            mv.visitLineNumber(29, l5);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{"java/lang/Object"}, 0, null);
            mv.visitFieldInsn(GETSTATIC, "com/ksyun/media/player/misc/e", "a", "Lcom/ksyun/media/player/misc/e;");
            mv.visitVarInsn(ALOAD, 0);
            mv.visitInsn(MONITOREXIT);
            mv.visitLabel(l1);
            mv.visitInsn(ARETURN);
            mv.visitLabel(l2);
            mv.visitLineNumber(30, l2);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{"java/lang/Throwable"});
            mv.visitVarInsn(ASTORE, 1);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitInsn(MONITOREXIT);
            mv.visitLabel(l3);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitInsn(ATHROW);
            mv.visitMaxs(2, 2);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "a", "(Landroid/content/Context;)V", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(35, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitFieldInsn(PUTFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLineNumber(36, l1);
            mv.visitInsn(RETURN);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l2, 0);
            mv.visitLocalVariable("paramContext", "Landroid/content/Context;", null, l0, l2, 1);
            mv.visitMaxs(2, 2);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "a", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(40, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "b", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitFieldInsn(PUTFIELD, "com/ksyun/media/player/misc/e", "c", "Ljava/lang/String;");
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLineNumber(41, l1);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "b", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitFieldInsn(PUTFIELD, "com/ksyun/media/player/misc/e", "d", "Ljava/lang/String;");
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLineNumber(42, l2);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 3);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "b", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitFieldInsn(PUTFIELD, "com/ksyun/media/player/misc/e", "e", "Ljava/lang/String;");
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLineNumber(43, l3);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 4);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "b", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitFieldInsn(PUTFIELD, "com/ksyun/media/player/misc/e", "f", "Ljava/lang/String;");
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(44, l4);
            mv.visitInsn(RETURN);
            Label l5 = new Label();
            mv.visitLabel(l5);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l5, 0);
            mv.visitLocalVariable("paramString1", "Ljava/lang/String;", null, l0, l5, 1);
            mv.visitLocalVariable("paramString2", "Ljava/lang/String;", null, l0, l5, 2);
            mv.visitLocalVariable("paramString3", "Ljava/lang/String;", null, l0, l5, 3);
            mv.visitLocalVariable("paramString4", "Ljava/lang/String;", null, l0, l5, 4);
            mv.visitMaxs(3, 5);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "b", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(48, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "c", "Ljava/lang/String;");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "c", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(53, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "d", "Ljava/lang/String;");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "d", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(58, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "e", "Ljava/lang/String;");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "e", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(63, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "f", "Ljava/lang/String;");
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "f", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(68, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            Label l1 = new Label();
            mv.visitJumpInsn(IFNONNULL, l1);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLineNumber(69, l2);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            mv.visitLabel(l1);
            mv.visitLineNumber(71, l1);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
            mv.visitInsn(DUP);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
            mv.visitVarInsn(ASTORE, 1);
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLineNumber(73, l3);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "android/content/Context", "getPackageName", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitIntInsn(BIPUSH, 59);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;", false);
            mv.visitFieldInsn(GETSTATIC, "android/os/Build$VERSION", "RELEASE", "Ljava/lang/String;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitIntInsn(BIPUSH, 59);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;", false);
            mv.visitFieldInsn(GETSTATIC, "android/os/Build", "MODEL", "Ljava/lang/String;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitInsn(POP);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(75, l4);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "b", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitInsn(ARETURN);
            Label l5 = new Label();
            mv.visitLabel(l5);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l5, 0);
            mv.visitLocalVariable("localStringBuilder", "Ljava/lang/StringBuilder;", null, l3, l5, 1);
            mv.visitMaxs(2, 2);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "g", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(80, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            Label l1 = new Label();
            mv.visitJumpInsn(IFNONNULL, l1);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLineNumber(81, l2);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            mv.visitLabel(l1);
            mv.visitLineNumber(83, l1);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitInsn(ACONST_NULL);
            mv.visitVarInsn(ASTORE, 1);
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLineNumber(84, l3);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "h", "()Ljava/lang/String;", false);
            mv.visitVarInsn(ASTORE, 2);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(85, l4);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKESTATIC, "android/text/TextUtils", "isEmpty", "(Ljava/lang/CharSequence;)Z", false);
            Label l5 = new Label();
            mv.visitJumpInsn(IFEQ, l5);
            Label l6 = new Label();
            mv.visitLabel(l6);
            mv.visitLineNumber(86, l6);
            mv.visitLdcInsn("ffffffffff");
            mv.visitVarInsn(ASTORE, 2);
            mv.visitLabel(l5);
            mv.visitLineNumber(88, l5);
            mv.visitFrame(Opcodes.F_APPEND, 2, new Object[]{"java/lang/String", "java/lang/String"}, 0, null);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "i", "()Ljava/lang/String;", false);
            mv.visitVarInsn(ASTORE, 3);
            Label l7 = new Label();
            mv.visitLabel(l7);
            mv.visitLineNumber(89, l7);
            mv.visitVarInsn(ALOAD, 3);
            mv.visitMethodInsn(INVOKESTATIC, "android/text/TextUtils", "isEmpty", "(Ljava/lang/CharSequence;)Z", false);
            Label l8 = new Label();
            mv.visitJumpInsn(IFEQ, l8);
            Label l9 = new Label();
            mv.visitLabel(l9);
            mv.visitLineNumber(90, l9);
            mv.visitLdcInsn("ffffffffff");
            mv.visitVarInsn(ASTORE, 3);
            mv.visitLabel(l8);
            mv.visitLineNumber(92, l8);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{"java/lang/String"}, 0, null);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "k", "()Ljava/lang/String;", false);
            mv.visitVarInsn(ASTORE, 4);
            Label l10 = new Label();
            mv.visitLabel(l10);
            mv.visitLineNumber(93, l10);
            mv.visitVarInsn(ALOAD, 4);
            mv.visitMethodInsn(INVOKESTATIC, "android/text/TextUtils", "isEmpty", "(Ljava/lang/CharSequence;)Z", false);
            Label l11 = new Label();
            mv.visitJumpInsn(IFEQ, l11);
            Label l12 = new Label();
            mv.visitLabel(l12);
            mv.visitLineNumber(94, l12);
            mv.visitLdcInsn("ffffffffff");
            mv.visitVarInsn(ASTORE, 4);
            mv.visitLabel(l11);
            mv.visitLineNumber(96, l11);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{"java/lang/String"}, 0, null);
            mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
            mv.visitInsn(DUP);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitLdcInsn("-");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
            mv.visitInsn(DUP);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
            mv.visitVarInsn(ALOAD, 4);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitVarInsn(ALOAD, 3);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "com/ksyun/media/player/misc/e", "a", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
            mv.visitVarInsn(ASTORE, 1);
            Label l13 = new Label();
            mv.visitLabel(l13);
            mv.visitLineNumber(98, l13);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKESPECIAL, "com/ksyun/media/player/misc/e", "b", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitInsn(ARETURN);
            Label l14 = new Label();
            mv.visitLabel(l14);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l14, 0);
            mv.visitLocalVariable("str1", "Ljava/lang/String;", null, l3, l14, 1);
            mv.visitLocalVariable("str2", "Ljava/lang/String;", null, l4, l14, 2);
            mv.visitLocalVariable("str3", "Ljava/lang/String;", null, l7, l14, 3);
            mv.visitLocalVariable("str4", "Ljava/lang/String;", null, l10, l14, 4);
            mv.visitMaxs(4, 5);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "a", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            Label l1 = new Label();
            Label l2 = new Label();
            mv.visitTryCatchBlock(l0, l1, l2, "java/security/NoSuchAlgorithmException");
            mv.visitLabel(l0);
            mv.visitLineNumber(106, l0);
            mv.visitLdcInsn("MD5");
            mv.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "([B)[B", false);
            mv.visitVarInsn(ASTORE, 2);
            mv.visitLabel(l1);
            mv.visitLineNumber(111, l1);
            Label l3 = new Label();
            mv.visitJumpInsn(GOTO, l3);
            mv.visitLabel(l2);
            mv.visitLineNumber(108, l2);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{"java/security/NoSuchAlgorithmException"});
            mv.visitVarInsn(ASTORE, 3);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(110, l4);
            mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
            mv.visitInsn(DUP);
            mv.visitLdcInsn("Huh, MD5 should be supported?");
            mv.visitVarInsn(ALOAD, 3);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", false);
            mv.visitInsn(ATHROW);
            mv.visitLabel(l3);
            mv.visitLineNumber(112, l3);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{"[B"}, 0, null);
            mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
            mv.visitInsn(DUP);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitInsn(ARRAYLENGTH);
            mv.visitInsn(ICONST_2);
            mv.visitInsn(IMUL);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(I)V", false);
            mv.visitVarInsn(ASTORE, 3);
            Label l5 = new Label();
            mv.visitLabel(l5);
            mv.visitLineNumber(113, l5);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitVarInsn(ASTORE, 4);
            mv.visitVarInsn(ALOAD, 4);
            mv.visitInsn(ARRAYLENGTH);
            mv.visitVarInsn(ISTORE, 5);
            mv.visitInsn(ICONST_0);
            mv.visitVarInsn(ISTORE, 6);
            Label l6 = new Label();
            mv.visitLabel(l6);
            mv.visitFrame(Opcodes.F_FULL, 7, new Object[]{"com/ksyun/media/player/misc/e", "java/lang/String", "[B", "java/lang/StringBuilder", "[B", Opcodes.INTEGER, Opcodes.INTEGER}, 0, new Object[]{});
            mv.visitVarInsn(ILOAD, 6);
            mv.visitVarInsn(ILOAD, 5);
            Label l7 = new Label();
            mv.visitJumpInsn(IF_ICMPGE, l7);
            mv.visitVarInsn(ALOAD, 4);
            mv.visitVarInsn(ILOAD, 6);
            mv.visitInsn(BALOAD);
            mv.visitVarInsn(ISTORE, 7);
            Label l8 = new Label();
            mv.visitLabel(l8);
            mv.visitLineNumber(115, l8);
            mv.visitVarInsn(ILOAD, 7);
            mv.visitIntInsn(SIPUSH, 255);
            mv.visitInsn(IAND);
            mv.visitIntInsn(BIPUSH, 16);
            Label l9 = new Label();
            mv.visitJumpInsn(IF_ICMPGE, l9);
            Label l10 = new Label();
            mv.visitLabel(l10);
            mv.visitLineNumber(116, l10);
            mv.visitVarInsn(ALOAD, 3);
            mv.visitLdcInsn("0");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitInsn(POP);
            mv.visitLabel(l9);
            mv.visitLineNumber(118, l9);
            mv.visitFrame(Opcodes.F_APPEND, 1, new Object[]{Opcodes.INTEGER}, 0, null);
            mv.visitVarInsn(ALOAD, 3);
            mv.visitVarInsn(ILOAD, 7);
            mv.visitIntInsn(SIPUSH, 255);
            mv.visitInsn(IAND);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toHexString", "(I)Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitInsn(POP);
            Label l11 = new Label();
            mv.visitLabel(l11);
            mv.visitLineNumber(113, l11);
            mv.visitIincInsn(6, 1);
            mv.visitJumpInsn(GOTO, l6);
            mv.visitLabel(l7);
            mv.visitLineNumber(120, l7);
            mv.visitFrame(Opcodes.F_FULL, 4, new Object[]{"com/ksyun/media/player/misc/e", "java/lang/String", "[B", "java/lang/StringBuilder"}, 0, new Object[]{});
            mv.visitVarInsn(ALOAD, 3);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
            mv.visitInsn(ARETURN);
            Label l12 = new Label();
            mv.visitLabel(l12);
            mv.visitLocalVariable("arrayOfByte1", "[B", null, l1, l2, 2);
            mv.visitLocalVariable("localNoSuchAlgorithmException", "Ljava/security/NoSuchAlgorithmException;", null, l4, l3, 3);
            mv.visitLocalVariable("k", "I", null, l8, l11, 7);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l12, 0);
            mv.visitLocalVariable("paramString", "Ljava/lang/String;", null, l0, l12, 1);
            mv.visitLocalVariable("arrayOfByte1", "[B", null, l3, l12, 2);
            mv.visitLocalVariable("localStringBuilder", "Ljava/lang/StringBuilder;", null, l5, l12, 3);
            mv.visitMaxs(4, 8);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE, "b", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            Label l1 = new Label();
            Label l2 = new Label();
            mv.visitTryCatchBlock(l0, l1, l2, "java/lang/Exception");
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLineNumber(125, l3);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKESTATIC, "android/text/TextUtils", "isEmpty", "(Ljava/lang/CharSequence;)Z", false);
            mv.visitJumpInsn(IFEQ, l0);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(126, l4);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            mv.visitLabel(l0);
            mv.visitLineNumber(130, l0);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitTypeInsn(NEW, "java/lang/String");
            mv.visitInsn(DUP);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            mv.visitLdcInsn("UTF-8");
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/lang/String;)V", false);
            mv.visitVarInsn(ASTORE, 2);
            Label l5 = new Label();
            mv.visitLabel(l5);
            mv.visitLineNumber(131, l5);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitLdcInsn("UTF-8");
            mv.visitMethodInsn(INVOKESTATIC, "java/net/URLEncoder", "encode", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitLabel(l1);
            mv.visitInsn(ARETURN);
            mv.visitLabel(l2);
            mv.visitLineNumber(133, l2);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{"java/lang/Exception"});
            mv.visitVarInsn(ASTORE, 2);
            Label l6 = new Label();
            mv.visitLabel(l6);
            mv.visitLineNumber(134, l6);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l7 = new Label();
            mv.visitLabel(l7);
            mv.visitLocalVariable("str", "Ljava/lang/String;", null, l5, l2, 2);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l3, l7, 0);
            mv.visitLocalVariable("paramString", "Ljava/lang/String;", null, l3, l7, 1);
            mv.visitMaxs(4, 3);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE, "h", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(139, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE, "i", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(144, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            Label l1 = new Label();
            mv.visitJumpInsn(IFNONNULL, l1);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLineNumber(145, l2);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            mv.visitLabel(l1);
            mv.visitLineNumber(147, l1);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            mv.visitMethodInsn(INVOKEVIRTUAL, "android/content/Context", "getContentResolver", "()Landroid/content/ContentResolver;", false);
            mv.visitLdcInsn("android_id");
            mv.visitMethodInsn(INVOKESTATIC, "android/provider/Settings$Secure", "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitInsn(ARETURN);
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l3, 0);
            mv.visitMaxs(2, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE, "j", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(152, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE, "k", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(157, l0);
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l1, 0);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PRIVATE, "c", "(Ljava/lang/String;)Z", null, null);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(162, l0);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            Label l1 = new Label();
            mv.visitJumpInsn(IFNONNULL, l1);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitLineNumber(163, l2);
            mv.visitInsn(ICONST_0);
            mv.visitInsn(IRETURN);
            mv.visitLabel(l1);
            mv.visitLineNumber(165, l1);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, "com/ksyun/media/player/misc/e", "g", "Landroid/content/Context;");
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "android/content/Context", "checkCallingOrSelfPermission", "(Ljava/lang/String;)I", false);
            Label l3 = new Label();
            mv.visitJumpInsn(IFNE, l3);
            mv.visitInsn(ICONST_1);
            Label l4 = new Label();
            mv.visitJumpInsn(GOTO, l4);
            mv.visitLabel(l3);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitInsn(ICONST_0);
            mv.visitLabel(l4);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{Opcodes.INTEGER});
            mv.visitInsn(IRETURN);
            Label l5 = new Label();
            mv.visitLabel(l5);
            mv.visitLocalVariable("this", "Lcom/ksyun/media/player/misc/e;", null, l0, l5, 0);
            mv.visitLocalVariable("paramString", "Ljava/lang/String;", null, l0, l5, 1);
            mv.visitMaxs(2, 2);
            mv.visitEnd();
        }
        cw.visitEnd();

        return cw.toByteArray();
    }
}
