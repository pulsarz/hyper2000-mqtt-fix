// Post-analysis script: find functions referencing MQTT/AT/WiFi strings and decompile them.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DumpMqttDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = System.getProperty(\"user.dir\") + \"/ghidra_out/mqtt_decomp.c\";
        String[] keywords = new String[] {
            "AT+MQTT", "MQTT_CONNECT", "MQTT_DISCONNECT", "MQTT_SUB",
            "AT+WJAP", "AT+WAUTOCONN", "AT+WMODE", "AT+RST", "AT+RESTORE",
            "WIFI_CONNECT", "WIFI_DISCONNECT", "WIFI_R", "WIFI_T",
            "wifi_sendtask", "wifi_rectask", "SocketDown", "AT+WRSSI"
        };

        Map<Function, Set<String>> funcHits = new LinkedHashMap<>();
        List<String> allStrings = new ArrayList<>();

        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext()) {
            Data data = dit.next();
            if (!data.hasStringValue()) continue;
            Object val = data.getValue();
            if (val == null) continue;
            String s = val.toString();
            String su = s.toUpperCase();
            boolean match = false;
            for (String kw : keywords) {
                if (su.contains(kw.toUpperCase())) {
                    match = true;
                    break;
                }
            }
            if (!match) continue;
            String clean = s.replace("\r", "\\r").replace("\n", "\\n");
            allStrings.add(data.getAddress() + " : " + clean);
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
            while (refs.hasNext()) {
                Reference r = refs.next();
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) {
                    funcHits.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(
                        data.getAddress() + ":" + clean
                    );
                }
            }
        }

        // Also include direct callers of all matched functions
        Set<Function> toDecompile = new LinkedHashSet<>(funcHits.keySet());
        for (Function f : new ArrayList<>(funcHits.keySet())) {
            for (Function caller : f.getCallingFunctions(monitor)) {
                toDecompile.add(caller);
            }
        }

        // Also grab any functions in the AT+MQTT / WIFI_R regions that didn't get string xrefs directly
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            long ep = f.getEntryPoint().getOffset();
            if ((ep >= 0x0800c3d0L && ep <= 0x0800d600L) || (ep >= 0x0801b400L && ep <= 0x0801bc50L)) {
                toDecompile.add(f);
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.println("// === MATCHED STRINGS (" + allStrings.size() + ") ===");
            for (String s : allStrings) {
                pw.println("// " + s);
            }
            pw.println();
            pw.println("// === FUNCTIONS TO DECOMPILE (" + toDecompile.size() + ") ===");
            for (Function f : toDecompile) {
                Set<String> hits = funcHits.get(f);
                pw.println("// " + f.getName() + " @ " + f.getEntryPoint() +
                    (hits != null ? " hits=" + hits : ""));
            }
            pw.println();

            for (Function f : toDecompile) {
                pw.println("/* ============================================================");
                pw.println(" * Function: " + f.getName() + " @ " + f.getEntryPoint());
                Set<String> hits = funcHits.get(f);
                if (hits != null) {
                    pw.println(" * String refs: " + hits);
                }
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
                    pw.println("// Decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
                }
                pw.println();
            }
        }
        decomp.dispose();
        println("Wrote decompiled MQTT functions to " + outPath + " (count=" + toDecompile.size() + ")");
    }
}
