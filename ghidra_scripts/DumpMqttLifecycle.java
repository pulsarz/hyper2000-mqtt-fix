// Find and decompile all functions referencing wifi_status (0x2000ed44), cur_state (0x2000f014),
// AT_TABLE (0x2000013c), wifi_send_sem (0x200004a4), plus loop10ms_task and FUN_08019194.
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

public class DumpMqttLifecycle extends GhidraScript {
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
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/mqtt_lifecycle.c\";

        // Key SRAM addresses to track across the entire binary
        long[] watchAddrs = new long[] {
            0x2000ed44L, // wifi_status
            0x2000f014L, // cur_state
            0x2000f020L, // pending_state
            0x2000efbcL, // base used with +0x58 -> cur_state
            0x2000013cL, // AT_TABLE
            0x20000138L, // AT_TABLE - 4
            0x200004a4L, // wifi_send_sem
            0x2000d0a4L, // placeholder
            0x20011794L, // state_1b7c0
        };

        // Scan flash for 32-bit literal pool entries matching any watchAddr (or within +/- 0x10 of wifi_status/cur_state)
        Map<Function, Set<String>> hits = new LinkedHashMap<>();
        long start = 0x08005000L;
        long end = 0x0802d000L;
        for (long a = start; a < end; a += 4) {
            long val = Integer.toUnsignedLong(mem.getInt(toAddr(a)));
            String tag = null;
            if (val >= 0x2000ed40L && val <= 0x2000ed60L) tag = String.format("wifi_status(0x%08x)", val);
            else if (val >= 0x2000f010L && val <= 0x2000f034L) tag = String.format("cur_state(0x%08x)", val);
            else if (val == 0x2000efbcL) tag = "cur_state_base(0x2000efbc)";
            else if (val == 0x2000013cL || val == 0x20000138L) tag = String.format("AT_TABLE(0x%08x)", val);
            else if (val == 0x200004a4L) tag = "wifi_send_sem(0x200004a4)";
            if (tag != null) {
                ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(toAddr(a));
                while (rit.hasNext()) {
                    Reference r = rit.next();
                    Function f = getFunctionContaining(r.getFromAddress());
                    if (f != null) {
                        hits.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(tag + "@lit_0x" + Long.toHexString(a));
                    }
                }
            }
        }

        // Also explicitly include loop10ms_task (0x08029e38), FUN_08019194, FUN_0800c83c (entry 1), FUN_0800cc88 (entry 2), FUN_0800cd24 (entry 4)
        long[] extra = new long[] { 0x08029e38L, 0x08019194L, 0x0800c83cL, 0x0800cc88L, 0x0800cd24L, 0x0800c414L, 0x0800c500L };
        for (long e : extra) {
            Function f = ensureFunc(e);
            if (f != null) hits.computeIfAbsent(f, k -> new LinkedHashSet<>()).add("explicit");
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.println("// Total functions touching Wi-Fi/MQTT state: " + hits.size());
            for (Map.Entry<Function, Set<String>> e : hits.entrySet()) {
                pw.println("// " + e.getKey().getName() + " @ " + e.getKey().getEntryPoint() + " : " + e.getValue());
            }
            pw.println();
            for (Map.Entry<Function, Set<String>> e : hits.entrySet()) {
                Function f = e.getKey();
                long ep = f.getEntryPoint().getOffset();
                // Skip ones we already read in full (0802ad68, 0802afc8, 0801b500, 0800c3cc, 0800c870..0800d41c)
                if (ep == 0x0802ad68L || ep == 0x0802afc8L || ep == 0x0801b500L || ep == 0x0800c3ccL) continue;
                pw.println("/* ============================================================");
                pw.println(" * Function: " + f.getName() + " @ " + f.getEntryPoint());
                pw.println(" * Refs: " + e.getValue());
                Set<Function> callers = f.getCallingFunctions(monitor);
                if (!callers.isEmpty()) {
                    List<String> cn = new ArrayList<>();
                    for (Function c : callers) cn.add(c.getName() + "@" + c.getEntryPoint());
                    pw.println(" * Callers: " + cn);
                }
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
        println("Wrote " + hits.size() + " lifecycle functions to " + outPath);
    }
}
