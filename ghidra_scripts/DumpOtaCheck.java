// Decompile ota_rectask, ota_httptask, and otareq/CRC/MD5 handlers to see OTA validation rules.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DumpOtaCheck extends GhidraScript {
    private long readU32(Memory mem, long addr) throws Exception {
        return Integer.toUnsignedLong(mem.getInt(toAddr(addr)));
    }

    private Function ensureFunc(long rawAddr, String name) throws Exception {
        long addr = rawAddr & ~1L;
        if (addr < 0x08005000L || addr >= 0x08030000L) return null;
        Address a = toAddr(addr);
        if (getInstructionAt(a) == null) disassemble(a);
        Function f = getFunctionAt(a);
        if (f == null) f = createFunction(a, name);
        return f;
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/ota_decomp.c\";

        long otaRecAddr  = readU32(mem, 0x0802200cL);
        long otaHttpAddr = readU32(mem, 0x08022020L);

        Set<Function> toDecomp = new LinkedHashSet<>();
        Function fRec  = ensureFunc(otaRecAddr, "ota_rectask");
        Function fHttp = ensureFunc(otaHttpAddr, "ota_httptask");
        if (fRec != null) toDecomp.add(fRec);
        if (fHttp != null) toDecomp.add(fHttp);

        String[] keywords = new String[] {
            "otareq", "ota_continue", "CRC Error", "OTA Timeout", "firmware/upgrade",
            "firmware/new", "md5", "sign", "MASTER"
        };

        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext()) {
            Data d = dit.next();
            if (!d.hasStringValue() || d.getValue() == null) continue;
            String s = d.getValue().toString();
            for (String kw : keywords) {
                if (s.contains(kw)) {
                    ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                    while (rit.hasNext()) {
                        Reference r = rit.next();
                        Function f = getFunctionContaining(r.getFromAddress());
                        if (f != null && f.getEntryPoint().getOffset() != 0x08007d44L
                            && f.getEntryPoint().getOffset() != 0x0800e4f8L
                            && f.getEntryPoint().getOffset() != 0x0800e74cL
                            && f.getEntryPoint().getOffset() != 0x08014e74L) {
                            toDecomp.add(f);
                        }
                    }
                    break;
                }
            }
        }

        // Also include direct callees of ota_rectask and ota_httptask
        for (Function p : new Function[]{fRec, fHttp}) {
            if (p == null) continue;
            for (Function c : p.getCalledFunctions(monitor)) {
                long ep = c.getEntryPoint().getOffset();
                if (ep >= 0x08006000L && ep < 0x0802b800L) toDecomp.add(c);
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.printf("// ota_rectask  = 0x%08x\n", otaRecAddr);
            pw.printf("// ota_httptask = 0x%08x\n", otaHttpAddr);
            pw.println("// Functions (" + toDecomp.size() + "):");
            for (Function f : toDecomp) pw.println("//  " + f.getName() + " @ " + f.getEntryPoint());
            pw.println();
            for (Function f : toDecomp) {
                pw.println("/* ============================================================");
                pw.println(" * Function: " + f.getName() + " @ " + f.getEntryPoint());
                pw.println(" * ============================================================ */");
                DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    pw.println(res.getDecompiledFunction().getC());
                } else {
                    pw.println("// Decompile failed");
                }
                pw.println();
            }
        }
        decomp.dispose();
        println("Wrote " + toDecomp.size() + " OTA functions to " + outPath);
    }
}
