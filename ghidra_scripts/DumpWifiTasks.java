// Decompile wifi_sendtask, wifi_rectask, their callees, and all AT+MQTT/WiFi handlers.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DumpWifiTasks extends GhidraScript {
    private Function ensureFunc(long rawAddr, String name) throws Exception {
        long addr = rawAddr & ~1L;
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
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/wifi_tasks.c\";
        Set<Function> toDecomp = new LinkedHashSet<>();

        Function fSend = ensureFunc(0x0802afc8L, "wifi_sendtask");
        Function fRec  = ensureFunc(0x0802ad68L, "wifi_rectask");
        if (fSend != null) toDecomp.add(fSend);
        if (fRec != null)  toDecomp.add(fRec);

        long[] atHandlers = new long[] {
            0x0800c3ccL, // AT+RST
            0x0800c870L, // AT+MQTT / MQTT_CONNECT
            0x0800c8c0L, // AT+MQTT=1
            0x0800c904L, // AT+MQTT=2
            0x0800c944L, // AT+MQTT=3,2
            0x0800c980L, // AT+MQTT=4
            0x0800c9dcL, // AT+MQTT=5
            0x0800ca20L, // AT+MQTT=6
            0x0800ca64L, // AT+MQTT=7
            0x0800caa8L, // AT+MQTTPUB
            0x0800cb00L, // AT+MQTTPUBRAW
            0x0800cb6cL, // MQTTPUBRAW data / ERROR
            0x0800cbb8L, // AT+MQTTSUB
            0x0800cc38L, // HW reset / ready
            0x0800d008L, // AT+RESTORE
            0x0800d1a0L, // AT+WAUTOCONN=0
            0x0800d1ecL, // AT+WJAP
            0x0800d270L, // AT+WJAP?
            0x0800d384L, // AT+WMODE=1,0
            0x0800d41cL, // AT+WRSSI
        };
        for (long h : atHandlers) {
            Function fh = ensureFunc(h, null);
            if (fh != null) toDecomp.add(fh);
        }

        // Add direct callees of wifi_sendtask and wifi_rectask
        for (Function parent : new Function[]{fSend, fRec}) {
            if (parent == null) continue;
            for (Function c : parent.getCalledFunctions(monitor)) {
                long ep = c.getEntryPoint().getOffset();
                if (ep >= 0x08006000L && ep < 0x0802b800L) {
                    toDecomp.add(c);
                }
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
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
