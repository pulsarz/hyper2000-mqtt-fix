// Decompile FUN_080087a8 (BLESPP RX handler) and all BLE OTA chunk/control handlers in MASTER_v2.1.47.bin.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DumpBleOtaFw extends GhidraScript {
    private Function ensureFunc(long addr) throws Exception {
        Address a = toAddr(addr & ~1L);
        if (getInstructionAt(a) == null) disassemble(a);
        Function f = getFunctionAt(a);
        if (f == null) f = createFunction(a, null);
        return f;
    }

    @Override
    public void run() throws Exception {
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/ble_ota_fw.c\";
        Set<Function> funcs = new LinkedHashSet<>();

        Function fMain = ensureFunc(0x080087a8L);
        if (fMain != null) {
            funcs.add(fMain);
            for (Function c : fMain.getCalledFunctions(monitor)) {
                long ep = c.getEntryPoint().getOffset();
                if (ep >= 0x08007000L && ep < 0x0801b000L && ep != 0x080079e8L) {
                    funcs.add(c);
                }
            }
        }
        // Also check FUN_080089b8 (BLE TX) and FUN_080083d8 / FUN_08008430
        funcs.add(ensureFunc(0x080089b8L));

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.println("// Functions (" + funcs.size() + "):");
            for (Function f : funcs) pw.println("//  " + f.getName() + " @ " + f.getEntryPoint());
            pw.println();
            for (Function f : funcs) {
                if (f == null) continue;
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
        println("Wrote " + funcs.size() + " BLE OTA functions to " + outPath);
    }
}
