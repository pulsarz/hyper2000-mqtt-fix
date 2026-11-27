// Decompile MQTT TX queue (FUN_0800fe3c, FUN_0800ff78, FUN_0800bc34), MQTT RX handler (FUN_080109e8),
// and Wi-Fi UART RX ISR (IRQ 0x27 = vector 0x27+16) to inspect all possible MQTT hang paths.
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

public class DumpMqttQueueAndRx extends GhidraScript {
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
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/mqtt_queue_rx.c\";

        // Vector 16 + 0x27 = 55 (USART3 on STM32/GD32, configured in FUN_0801b44c line 418: NVIC(0x27, 6, 0))
        long uartIsr = Integer.toUnsignedLong(mem.getInt(toAddr(0x08005000L + (16 + 0x27) * 4L)));

        long[] addrs = new long[] {
            0x0800fe3cL, // MQTT enqueue
            0x0800ff78L, // MQTT dequeue
            0x0800bc34L, // secondary dequeue
            0x080109e8L, // MQTT_SUB handler
            0x08010cbcL, // called from FUN_08019194 & FUN_08012e1c
            0x08010e04L, // called every 1s in FUN_08019194
            0x0800d768L, // called every 1s in FUN_08019194
            uartIsr
        };

        Set<Function> funcs = new LinkedHashSet<>();
        for (long a : addrs) {
            Function f = ensureFunc(a);
            if (f != null) funcs.add(f);
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.printf("// UART ISR (IRQ 0x27, vec 55) = 0x%08x\n\n", uartIsr);
            for (Function f : funcs) {
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
        println("Wrote " + funcs.size() + " functions to " + outPath);
    }
}
