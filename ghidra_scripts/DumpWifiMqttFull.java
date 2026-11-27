// Dump wifi_sendtask, wifi_rectask, the 57-entry AT command table, and all MQTT/WiFi handlers.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DumpWifiMqttFull extends GhidraScript {
    private long readU32(Memory mem, long addr) throws Exception {
        return Integer.toUnsignedLong(mem.getInt(toAddr(addr)));
    }

    private Function ensureFunc(long rawAddr, String name) throws Exception {
        long addr = rawAddr & ~1L;
        if (addr < 0x08005000L || addr >= 0x08030000L) return null;
        Address a = toAddr(addr);
        if (getInstructionAt(a) == null) {
            disassemble(a);
        }
        Function f = getFunctionAt(a);
        if (f == null) {
            f = createFunction(a, name);
        } else if (name != null && f.getName().startsWith("FUN_")) {
            f.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
        }
        return f;
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/wifi_mqtt_full.c\";

        long wifiSendAddr = readU32(mem, 0x08021fe8L);
        long wifiRecAddr  = readU32(mem, 0x08021ffcL);
        long loop10msAddr = readU32(mem, 0x08021fc4L);
        long tableAddr    = readU32(mem, 0x0801b800L);
        long statePtr1    = readU32(mem, 0x0801b760L);
        long statePtr2    = readU32(mem, 0x0801b7c0L);
        long statePtr3    = readU32(mem, 0x0801b4f4L);
        long statePtr4    = readU32(mem, 0x0801b4f8L);
        long statePtr5    = readU32(mem, 0x0801b8d0L);
        long statePtr6    = readU32(mem, 0x0801b8d4L);
        long statePtr7    = readU32(mem, 0x0801bb74L);
        long statePtr8    = readU32(mem, 0x0801bb78L);
        long statePtr9    = readU32(mem, 0x0801bb7cL);

        Set<Function> toDecomp = new LinkedHashSet<>();

        Function fSend = ensureFunc(wifiSendAddr, "wifi_sendtask");
        Function fRec  = ensureFunc(wifiRecAddr, "wifi_rectask");
        if (fSend != null) toDecomp.add(fSend);
        if (fRec != null)  toDecomp.add(fRec);

        // Also add direct callees of wifi_sendtask and wifi_rectask (within flash)
        if (fSend != null) {
            for (Function c : fSend.getCalledFunctions(monitor)) {
                long ep = c.getEntryPoint().getOffset();
                if (ep < 0x0802a000L && ep > 0x08006000L) toDecomp.add(c);
            }
        }
        if (fRec != null) {
            for (Function c : fRec.getCalledFunctions(monitor)) {
                long ep = c.getEntryPoint().getOffset();
                if (ep < 0x0802a000L && ep > 0x08006000L) toDecomp.add(c);
            }
        }

        // Parse 57-entry AT table at tableAddr (each 12 bytes)
        List<String> tableLines = new ArrayList<>();
        Map<Integer, Function> cmdFuncs = new LinkedHashMap<>();
        for (int i = 0; i < 0x39; i++) {
            long eaddr = tableAddr + i * 12L;
            int b0 = Byte.toUnsignedInt(mem.getByte(toAddr(eaddr)));
            int b1 = Byte.toUnsignedInt(mem.getByte(toAddr(eaddr + 1)));
            int b2 = Byte.toUnsignedInt(mem.getByte(toAddr(eaddr + 2)));
            int b3 = Byte.toUnsignedInt(mem.getByte(toAddr(eaddr + 3)));
            int w1 = mem.getInt(toAddr(eaddr + 4));
            long fn = readU32(mem, eaddr + 8);
            tableLines.add(String.format("  [%2d] cmdId=%2d (0x%02x) b1..3=[%d,%d,%d] w1=0x%08x fn=0x%08x",
                i, b0, b0, b1, b2, b3, w1, fn));
            Function f = ensureFunc(fn, String.format("at_cmd_%02d", b0));
            if (f != null) {
                cmdFuncs.put(b0, f);
                toDecomp.add(f);
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.printf("// wifi_sendtask = 0x%08x\n", wifiSendAddr);
            pw.printf("// wifi_rectask  = 0x%08x\n", wifiRecAddr);
            pw.printf("// loop10ms_task = 0x%08x\n", loop10msAddr);
            pw.printf("// AT_TABLE      = 0x%08x\n", tableAddr);
            pw.printf("// DAT_0801b760  = 0x%08x\n", statePtr1);
            pw.printf("// DAT_0801b7c0  = 0x%08x\n", statePtr2);
            pw.printf("// DAT_0801b4f4  = 0x%08x\n", statePtr3);
            pw.printf("// DAT_0801b4f8  = 0x%08x\n", statePtr4);
            pw.printf("// DAT_0801b8d0  = 0x%08x\n", statePtr5);
            pw.printf("// DAT_0801b8d4  = 0x%08x\n", statePtr6);
            pw.printf("// DAT_0801bb74  = 0x%08x\n", statePtr7);
            pw.printf("// DAT_0801bb78  = 0x%08x\n", statePtr8);
            pw.printf("// DAT_0801bb7c  = 0x%08x\n", statePtr9);
            pw.println("// === AT COMMAND TABLE (57 entries) ===");
            for (String l : tableLines) pw.println("// " + l);
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
        println("Wrote " + toDecomp.size() + " functions to " + outPath);
    }
}
