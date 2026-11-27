// Pre-analysis script: add SRAM memory block & disassemble Cortex-M vector table entries.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;

public class PreSetupCortexM extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address sramStart = toAddr(0x20000000L);
        if (mem.getBlock(sramStart) == null) {
            MemoryBlock sram = mem.createUninitializedBlock("SRAM", sramStart, 0x30000L, false);
            sram.setRead(true);
            sram.setWrite(true);
            sram.setExecute(false);
        }
        Address periphStart = toAddr(0x40000000L);
        if (mem.getBlock(periphStart) == null) {
            MemoryBlock periph = mem.createUninitializedBlock("PERIPH", periphStart, 0x100000L, false);
            periph.setRead(true);
            periph.setWrite(true);
            periph.setExecute(false);
            periph.setVolatile(true);
        }

        Register tmode = currentProgram.getLanguage().getRegister("TMode");
        Address base = toAddr(0x08005000L);
        // Parse first 96 vector table entries (word 1..95)
        for (int i = 1; i < 96; i++) {
            int vec = mem.getInt(base.add(i * 4L));
            long uvec = Integer.toUnsignedLong(vec);
            if (uvec >= 0x08005001L && uvec < 0x08030000L && (uvec & 1L) == 1L) {
                Address target = toAddr(uvec & ~1L);
                if (getInstructionAt(target) == null) {
                    if (tmode != null) {
                        currentProgram.getProgramContext().setRegisterValue(
                            target, target.add(1), new RegisterValue(tmode, BigInteger.ONE)
                        );
                    }
                    addEntryPoint(target);
                    disassemble(target);
                }
                if (getFunctionAt(target) == null) {
                    createFunction(target, i == 1 ? "Reset_Handler" : null);
                }
            }
        }
    }
}
