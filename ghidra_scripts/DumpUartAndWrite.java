// Decompile UART RX consumer (refs to 0x2000008c / 0x20000084), FUN_080107dc (properties/write),
// and check DAT_0801bb44 buffer size & all writers to cur_state / wifi_status.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DumpUartAndWrite extends GhidraScript {
    private Function ensureFunc(long addr) throws Exception {
        Address a = toAddr(addr & ~1L);
        if (getInstructionAt(a) == null) disassemble(a);
        Function f = getFunctionAt(a);
        if (f == null) f = createFunction(a, null);
        return f;
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/uart_and_write.c\";

        Set<Function> funcs = new LinkedHashSet<>();
        long[] watch = new long[] { 0x2000008cL, 0x20000084L, 0x200105a4L, 0x2000e5c8L };
        for (long a = 0x08005000L; a < 0x0802d000L; a += 4) {
            long val = Integer.toUnsignedLong(mem.getInt(toAddr(a)));
            for (long w : watch) {
                if (val == w) {
                    ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(toAddr(a));
                    while (rit.hasNext()) {
                        Reference r = rit.next();
                        Function f = getFunctionContaining(r.getFromAddress());
                        if (f != null && f.getEntryPoint().getOffset() != 0x0802ad68L) {
                            funcs.add(f);
                        }
                    }
                }
            }
        }
        funcs.add(ensureFunc(0x080107dcL)); // properties/write

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.printf("// DAT_0801bb44 (UART TX buf) = 0x%08x\n", Integer.toUnsignedLong(mem.getInt(toAddr(0x0801bb44L))));
            pw.printf("// DAT_0801bae0 (UART RX DMA buf) = 0x%08x\n", Integer.toUnsignedLong(mem.getInt(toAddr(0x0801bae0L))));
            pw.println("// Functions (" + funcs.size() + "):");
            for (Function f : funcs) pw.println("//  " + f.getName() + " @ " + f.getEntryPoint());
            pw.println();
            for (Function f : funcs) {
                pw.println("/* ============================================================");
                pw.println(" * Function: " + f.getName() + " @ " + f.getEntryPoint());
                pw.println(" * ============================================================ */");
                DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    pw.println(res.getDecompiledFunction().getC());
                }
                pw.println();
            }
        }
        decomp.dispose();
        println("Wrote " + funcs.size() + " functions to " + outPath);
    }
}
