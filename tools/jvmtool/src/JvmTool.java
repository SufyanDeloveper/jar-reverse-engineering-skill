import java.io.*;
import java.lang.classfile.*;
import java.lang.classfile.attribute.*;
import java.lang.classfile.constantpool.*;
import java.lang.classfile.instruction.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.*;
import java.util.zip.*;

public class JvmTool {
    record Finding(String id, String severity, String location, String evidence, String note) {}
    record Profile(Map<String,Object> data) {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) { usage(); System.exit(2); }
        String cmd = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (cmd) {
            case "profile" -> cmdProfile(rest);
            case "scan" -> cmdScan(rest);
            case "strings" -> cmdStrings(rest);
            case "apply-map" -> cmdApplyMap(rest);
            case "help", "-h", "--help" -> usage();
            default -> { System.err.println("Unknown command: " + cmd); usage(); System.exit(2); }
        }
    }

    static void usage() {
        System.out.println("JvmTool - static JVM analysis helper (no artifact execution)\n");
        System.out.println("Commands:");
        System.out.println("  profile <artifact.jar|class> [--json out.json]");
        System.out.println("  scan <artifact.jar|class> [--json out.json]");
        System.out.println("  strings <artifact.jar|class> [--out strings.txt]");
        System.out.println("  apply-map <artifact.jar> <map.tsv> --out mapped.jar");
        System.out.println("\nMap format (TSV): oldInternalName\tnewInternalName");
    }

    static Map<String,String> parseFlags(String[] args) {
        Map<String,String> m = new LinkedHashMap<>();
        List<String> pos = new ArrayList<>();
        for (int i=0;i<args.length;i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                String k = a.substring(2);
                String v = "true";
                if (i+1 < args.length && !args[i+1].startsWith("--")) { v = args[++i]; }
                m.put(k,v);
            } else pos.add(a);
        }
        for (int i=0;i<pos.size();i++) m.put("_"+i, pos.get(i));
        return m;
    }

    static byte[] readAll(InputStream in) throws IOException { return in.readAllBytes(); }

    static String sha256(Path p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(p)) {
            byte[] buf = new byte[1024*1024]; int r;
            while ((r=in.read(buf))>0) md.update(buf,0,r);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static List<ClassEntry> loadClasses(Path artifact) throws Exception {
        List<ClassEntry> out = new ArrayList<>();
        if (artifact.toString().endsWith(".class")) {
            byte[] b = Files.readAllBytes(artifact);
            out.add(new ClassEntry(artifact.getFileName().toString(), b));
            return out;
        }
        try (ZipFile zf = new ZipFile(artifact.toFile())) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory() || !e.getName().endsWith(".class")) continue;
                try (InputStream in = zf.getInputStream(e)) {
                    out.add(new ClassEntry(e.getName(), readAll(in)));
                }
            }
        }
        return out;
    }

    record ClassEntry(String name, byte[] bytes) {}


    static Map<String,Object> analyzeClass(ClassEntry ce) {
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("name", ce.name());
        try {
            ClassModel cm = ClassFile.of().parse(ce.bytes());
            m.put("valid", true);
            m.put("major", cm.majorVersion());
            m.put("minor", cm.minorVersion());
            m.put("access", cm.flags().flagsMask());
            m.put("thisClass", cm.thisClass().asInternalName());
            m.put("superClass", cm.superclass().map(sc -> sc.asInternalName()).orElse(null));
            m.put("interfaces", cm.interfaces().stream().map(i -> i.asInternalName()).toList());
            m.put("fields", cm.fields().size());
            m.put("methods", cm.methods().size());
            boolean hasSource = cm.findAttribute(java.lang.classfile.Attributes.sourceFile()).isPresent();
            boolean hasDebug = false, hasBootstrap = cm.findAttribute(java.lang.classfile.Attributes.bootstrapMethods()).isPresent();
            boolean hasInner = cm.findAttribute(java.lang.classfile.Attributes.innerClasses()).isPresent();
            boolean hasSignature = cm.findAttribute(java.lang.classfile.Attributes.signature()).isPresent();
            boolean hasRuntimeVisibleAnn = cm.findAttribute(java.lang.classfile.Attributes.runtimeVisibleAnnotations()).isPresent();
            boolean hasRuntimeInvisibleAnn = cm.findAttribute(java.lang.classfile.Attributes.runtimeInvisibleAnnotations()).isPresent();
            int branchCount=0, switchCount=0, invokeDynamic=0, reflectionRefs=0, cryptoRefs=0, dynamicLoadRefs=0, tryCatch=0;
            Set<String> strings = new LinkedHashSet<>();
            Set<String> refs = new LinkedHashSet<>();
            for (FieldModel fm : cm.fields()) {
                if (fm.findAttribute(java.lang.classfile.Attributes.signature()).isPresent()) hasSignature = true;
            }
            for (MethodModel mm : cm.methods()) {
                if (mm.findAttribute(java.lang.classfile.Attributes.signature()).isPresent()) hasSignature = true;
                if (mm.findAttribute(java.lang.classfile.Attributes.runtimeVisibleAnnotations()).isPresent()) hasRuntimeVisibleAnn = true;
                if (mm.findAttribute(java.lang.classfile.Attributes.runtimeInvisibleAnnotations()).isPresent()) hasRuntimeInvisibleAnn = true;
                var codeOpt = mm.findAttribute(java.lang.classfile.Attributes.code());
                if (codeOpt.isPresent()) {
                    CodeModel code = codeOpt.get();
                    tryCatch += code.exceptionHandlers().size();
                    for (Attribute<?> a : code.attributes()) {
                        String n = a.attributeName().stringValue();
                        if (n.equals("LocalVariableTable") || n.equals("LocalVariableTypeTable") || n.equals("LineNumberTable")) hasDebug = true;
                    }
                    for (CodeElement el : code) {
                        if (el instanceof BranchInstruction) branchCount++;
                        if (el instanceof TableSwitchInstruction || el instanceof LookupSwitchInstruction) switchCount++;
                        if (el instanceof InvokeDynamicInstruction idi) {
                            invokeDynamic++;
                            refs.add("invokedynamic:" + idi.name().stringValue());
                        }
                        if (el instanceof InvokeInstruction ii) {
                            String ref = ii.owner().asInternalName() + "." + ii.name().stringValue() + ii.type().stringValue();
                            refs.add(ref);
                            String owner = ii.owner().asInternalName();
                            String nm = ii.name().stringValue();
                            if ((owner.equals("java/lang/reflect/Method") && nm.equals("invoke")) || (owner.equals("java/lang/Class") && nm.equals("forName")) || owner.startsWith("java/lang/reflect/")) reflectionRefs++;
                            if (owner.startsWith("javax/crypto/") || owner.contains("Base64")) cryptoRefs++;
                            if (owner.equals("java/lang/ClassLoader") || owner.contains("URLClassLoader") || owner.equals("java/lang/invoke/MethodHandles$Lookup")) dynamicLoadRefs++;
                        }
                        if (el instanceof FieldInstruction fi) {
                            refs.add(fi.owner().asInternalName() + "." + fi.name().stringValue());
                        }
                        if (el instanceof ConstantInstruction ci) {
                            java.lang.constant.ConstantDesc cd = ci.constantValue();
                            if (cd instanceof String s) strings.add(s);
                        }
                    }
                }
            }
            m.put("sourceFile", hasSource);
            m.put("debugInfo", hasDebug);
            m.put("bootstrapMethods", hasBootstrap);
            m.put("innerClasses", hasInner);
            m.put("signature", hasSignature);
            m.put("annotations", hasRuntimeVisibleAnn || hasRuntimeInvisibleAnn);
            m.put("branchCount", branchCount);
            m.put("switchCount", switchCount);
            m.put("invokeDynamic", invokeDynamic);
            m.put("tryCatchHandlers", tryCatch);
            m.put("reflectionRefs", reflectionRefs);
            m.put("cryptoRefs", cryptoRefs);
            m.put("dynamicLoadRefs", dynamicLoadRefs);
            m.put("stringConstants", strings.size());
            m.put("sampleStrings", strings.stream().limit(20).toList());
            m.put("sampleRefs", refs.stream().limit(30).toList());
        } catch (Throwable t) {
            m.put("valid", false);
            m.put("error", String.valueOf(t));
        }
        return m;
    }


    static void writeJson(Path out, Object obj) throws Exception {
        Files.createDirectories(out.toAbsolutePath().getParent() == null ? Path.of(".") : out.toAbsolutePath().getParent());
        Files.writeString(out, toJson(obj, 0), StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    static String toJson(Object obj, int indent) {
        String pad = "  ".repeat(indent);
        String pad2 = "  ".repeat(indent+1);
        if (obj == null) return "null";
        if (obj instanceof String s) return "\"" + escapeJson(s) + "\"";
        if (obj instanceof Number || obj instanceof Boolean) return String.valueOf(obj);
        if (obj instanceof Map<?,?> map) {
            if (map.isEmpty()) return "{}";
            StringBuilder sb = new StringBuilder("{\n");
            int i=0;
            for (var e : map.entrySet()) {
                sb.append(pad2).append(toJson(String.valueOf(e.getKey()),0)).append(": ").append(toJson(e.getValue(), indent+1));
                if (++i < map.size()) sb.append(",");
                sb.append("\n");
            }
            sb.append(pad).append("}");
            return sb.toString();
        }
        if (obj instanceof Collection<?> col) {
            if (col.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[\n");
            int i=0;
            for (Object e : col) {
                sb.append(pad2).append(toJson(e, indent+1));
                if (++i < col.size()) sb.append(",");
                sb.append("\n");
            }
            sb.append(pad).append("]");
            return sb.toString();
        }
        return toJson(String.valueOf(obj), indent);
    }

    static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i=0;i<s.length();i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> { if (c < 32) sb.append(String.format("\\u%04x", (int)c)); else sb.append(c); }
            }
        }
        return sb.toString();
    }

    static void cmdProfile(String[] args) throws Exception {
        Map<String,String> f = parseFlags(args);
        Path artifact = Path.of(f.get("_0"));
        List<ClassEntry> classes = loadClasses(artifact);
        Map<String,Object> root = new LinkedHashMap<>();
        root.put("schema", "jvmtool.profile/v1");
        root.put("artifact", Map.of("path", artifact.toString(), "sha256", sha256(artifact), "size", Files.size(artifact)));
        List<Map<String,Object>> analyzed = new ArrayList<>();
        for (ClassEntry ce : classes) analyzed.add(analyzeClass(ce));
        root.put("classCount", analyzed.size());
        root.put("classes", analyzed);
        root.put("summary", summarize(analyzed));
        String json = toJson(root,0);
        if (f.containsKey("json")) writeJson(Path.of(f.get("json")), root);
        else System.out.println(json);
    }

    static Map<String,Object> summarize(List<Map<String,Object>> classes) {
        Map<String,Object> s = new LinkedHashMap<>();
        Map<Integer,Integer> majors = new TreeMap<>();
        int debug=0, src=0, boot=0, ann=0, valid=0;
        long branches=0,switches=0,indy=0,refl=0,crypto=0,dyn=0;
        for (Map<String,Object> c : classes) {
            if (Boolean.TRUE.equals(c.get("valid"))) valid++;
            Object mj = c.get("major"); if (mj instanceof Number n) majors.merge(n.intValue(),1,Integer::sum);
            if (Boolean.TRUE.equals(c.get("debugInfo"))) debug++;
            if (Boolean.TRUE.equals(c.get("sourceFile"))) src++;
            if (Boolean.TRUE.equals(c.get("bootstrapMethods"))) boot++;
            if (Boolean.TRUE.equals(c.get("annotations"))) ann++;
            branches += ((Number)c.getOrDefault("branchCount",0)).longValue();
            switches += ((Number)c.getOrDefault("switchCount",0)).longValue();
            indy += ((Number)c.getOrDefault("invokeDynamic",0)).longValue();
            refl += ((Number)c.getOrDefault("reflectionRefs",0)).longValue();
            crypto += ((Number)c.getOrDefault("cryptoRefs",0)).longValue();
            dyn += ((Number)c.getOrDefault("dynamicLoadRefs",0)).longValue();
        }
        s.put("validClasses", valid);
        s.put("majorVersions", majors);
        s.put("withDebugInfo", debug);
        s.put("withSourceFile", src);
        s.put("withBootstrapMethods", boot);
        s.put("withAnnotations", ann);
        s.put("totalBranches", branches);
        s.put("totalSwitches", switches);
        s.put("totalInvokeDynamic", indy);
        s.put("totalReflectionRefs", refl);
        s.put("totalCryptoRefs", crypto);
        s.put("totalDynamicLoadRefs", dyn);
        return s;
    }


    static void cmdScan(String[] args) throws Exception {
        Map<String,String> f = parseFlags(args);
        Path artifact = Path.of(f.get("_0"));
        List<ClassEntry> classes = loadClasses(artifact);
        List<Map<String,Object>> findings = new ArrayList<>();
        int shortNames=0, total=0, highEntropy=0;
        long refl=0, crypto=0, dyn=0, branches=0, switches=0, indy=0;
        for (ClassEntry ce : classes) {
            Map<String,Object> c = analyzeClass(ce);
            if (!Boolean.TRUE.equals(c.get("valid"))) continue;
            total++;
            String simple = ce.name().substring(ce.name().lastIndexOf('/')+1).replace(".class","");
            if (simple.contains("$")) simple = simple.substring(simple.lastIndexOf('$')+1);
            if (simple.matches("[a-zA-Z]{1,2}|[Il1O0]{1,3}")) shortNames++;
            branches += ((Number)c.getOrDefault("branchCount",0)).longValue();
            switches += ((Number)c.getOrDefault("switchCount",0)).longValue();
            indy += ((Number)c.getOrDefault("invokeDynamic",0)).longValue();
            refl += ((Number)c.getOrDefault("reflectionRefs",0)).longValue();
            crypto += ((Number)c.getOrDefault("cryptoRefs",0)).longValue();
            dyn += ((Number)c.getOrDefault("dynamicLoadRefs",0)).longValue();
            @SuppressWarnings("unchecked") List<String> ss = (List<String>) c.getOrDefault("sampleStrings", List.of());
            for (String s : ss) {
                if (s.length() >= 20 && s.length() <= 200) {
                    double e = entropy(s);
                    if (e > 4.5) highEntropy++;
                }
            }
            if (((Number)c.getOrDefault("tryCatchHandlers",0)).intValue() > 15 && ((Number)c.getOrDefault("branchCount",0)).intValue() > 80) {
                findings.add(finding("complex-control-flow","medium",ce.name(),"tryCatch="+c.get("tryCatchHandlers")+", branches="+c.get("branchCount"),"Heuristic: complex control flow may indicate obfuscation or legitimate complexity; verify with CFG/disassembly."));
            }
            if (((Number)c.getOrDefault("reflectionRefs",0)).intValue() > 5) {
                findings.add(finding("reflection-heavy-class","medium",ce.name(),"reflectionRefs="+c.get("reflectionRefs"),"Heuristic: reflection-heavy class; inspect string construction and dynamic targets."));
            }
        }
        if (total > 0 && shortNames * 100 / total >= 25) findings.add(finding("short-identifiers","medium","<artifact>", shortNames+"/"+total+" short class names","Heuristic; may indicate renaming/minimization/generated code."));
        if (highEntropy >= 20) findings.add(finding("high-entropy-strings","medium","<artifact>", String.valueOf(highEntropy)+" sampled high-entropy strings","Heuristic; may indicate encoding/encryption or legitimate tokens."));
        if (refl >= 20) findings.add(finding("reflection-usage","medium","<artifact>", "reflectionRefs="+refl,"Heuristic; verify context."));
        if (crypto >= 10) findings.add(finding("crypto-apis","medium","<artifact>", "cryptoRefs="+crypto,"Heuristic; may indicate string/resource encryption or normal crypto."));
        if (dyn >= 10) findings.add(finding("dynamic-loading","medium","<artifact>", "dynamicLoadRefs="+dyn,"Heuristic; may indicate custom loading/plugins/packing."));
        if (indy > 0 && switches > 0) findings.add(finding("indy-and-switches","low","<artifact>", "invokeDynamic="+indy+", switches="+switches,"May indicate modern Java/Kotlin patterns or obfuscation; verify."));

        Map<String,Object> root = new LinkedHashMap<>();
        root.put("schema", "jvmtool.scan/v1");
        root.put("artifact", Map.of("path", artifact.toString(), "sha256", sha256(artifact)));
        root.put("summary", Map.of("classes", total, "findings", findings.size(), "reflectionRefs", refl, "cryptoRefs", crypto, "dynamicLoadRefs", dyn));
        root.put("findings", findings);
        String json = toJson(root,0);
        if (f.containsKey("json")) writeJson(Path.of(f.get("json")), root);
        else System.out.println(json);
    }

    static Map<String,Object> finding(String id, String severity, String location, String evidence, String note) {
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("id", id); m.put("severity", severity); m.put("location", location); m.put("evidence", evidence); m.put("note", note);
        return m;
    }

    static double entropy(String s) {
        int[] freq = new int[256]; byte[] b = s.getBytes(StandardCharsets.UTF_8);
        for (byte x : b) freq[x & 0xff]++;
        double e=0; for (int c : freq) if (c>0) { double p=(double)c/b.length; e -= p * (Math.log(p)/Math.log(2)); }
        return e;
    }

    static void cmdStrings(String[] args) throws Exception {
        Map<String,String> f = parseFlags(args);
        Path artifact = Path.of(f.get("_0"));
        List<ClassEntry> classes = loadClasses(artifact);
        StringBuilder sb = new StringBuilder();
        for (ClassEntry ce : classes) {
            Map<String,Object> c = analyzeClass(ce);
            @SuppressWarnings("unchecked") List<String> ss = (List<String>) c.getOrDefault("sampleStrings", List.of());
            for (String s : ss) sb.append(ce.name()).append('\t').append(s.replace("\n","\\n")).append('\n');
        }
        if (f.containsKey("out")) Files.writeString(Path.of(f.get("out")), sb.toString(), StandardCharsets.UTF_8);
        else System.out.print(sb.toString());
    }

    static void cmdApplyMap(String[] args) throws Exception {
        System.err.println("apply-map is not implemented in this minimal build. Use evidence-based rename mapping tools and verify results.");
        System.exit(2);
    }
}
