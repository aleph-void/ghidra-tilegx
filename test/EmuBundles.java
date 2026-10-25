// Runs one bundle per case in Ghidra's p-code emulator and prints the destination register.
// The program is a raw file of 8-byte bundles imported at address 0; case k uses bundle k.
// Script args: <cases.txt> <outfile>
//   cases.txt lines: <mnemonic> <r1-hex> <r2-hex> <r3-hex> ...   (r1 = SrcA, r2 = SrcB, r3 = Dest)
//   output lines:    <mnemonic> <r3-hex after the bundle>  (or "<mnemonic> ERROR <message>")
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class EmuBundles extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<String> lines = Files.readAllLines(Path.of(args[0]));
		PrintStream out = new PrintStream(args[1]);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			int k = 0;
			for (String line : lines) {
				String[] f = line.trim().split("\\s+");
				Address a = toAddr(8L * k++);
				emu.writeRegister("r1", new BigInteger(f[1], 16));
				emu.writeRegister("r2", new BigInteger(f[2], 16));
				emu.writeRegister("r3", new BigInteger(f[3], 16));
				emu.writeRegister(emu.getPCRegister(), a.getOffset());
				if (!emu.step(monitor)) {
					out.println(f[0] + " ERROR " + emu.getLastError());
					continue;
				}
				out.printf("%s %016x%n", f[0], emu.readRegister("r3"));
			}
		}
		finally {
			emu.dispose();
		}
		out.close();
	}
}
