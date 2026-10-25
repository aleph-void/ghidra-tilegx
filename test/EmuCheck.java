// Runs the TILE-Gx p-code semantic tests produced by emu_tests.py in Ghidra's p-code emulator.
// The program must be emu.bin imported raw at address 0.
// Script args: <tests.txt> <outfile>
//   tests.txt lines: <name> <start-hex> <stop-hex> <init key=val,...|-> <expect key=val,...>
//   keys: register names, or m1:/m2:/m4:/m8:<hex address> for memory in the language's byte order
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class EmuCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		int pass = 0, fail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			String[] f = line.split("\\s+");
			String err = runOne(f);
			if (err == null) {
				pass++;
				out.println("PASS " + f[0]);
			}
			else {
				fail++;
				out.println("FAIL " + f[0] + ": " + err);
			}
		}
		out.printf("emulator tests: %d passed, %d failed%n", pass, fail);
		out.close();
	}

	private boolean bigEndian() {
		return currentProgram.getLanguage().isBigEndian();
	}

	private void put(EmulatorHelper emu, String k, BigInteger v) throws Exception {
		if (k.startsWith("m")) {
			int n = k.charAt(1) - '0';
			long a = Long.parseLong(k.substring(3), 16);
			byte[] b = new byte[n];
			for (int i = 0; i < n; i++) {
				b[bigEndian() ? n - 1 - i : i] = v.shiftRight(8 * i).byteValue();
			}
			emu.writeMemory(toAddr(a), b);
		}
		else {
			emu.writeRegister(k, v);
		}
	}

	private BigInteger get(EmulatorHelper emu, String k) throws Exception {
		if (k.startsWith("m")) {
			int n = k.charAt(1) - '0';
			long a = Long.parseLong(k.substring(3), 16);
			byte[] b = emu.readMemory(toAddr(a), n);
			BigInteger v = BigInteger.ZERO;
			for (int i = n - 1; i >= 0; i--) {
				v = v.shiftLeft(8).or(BigInteger.valueOf(b[bigEndian() ? n - 1 - i : i] & 0xff));
			}
			return v;
		}
		Register r = currentProgram.getRegister(k);
		BigInteger mask = BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE);
		return emu.readRegister(r).and(mask);
	}

	private String runOne(String[] f) throws Exception {
		Address start = toAddr(Long.parseUnsignedLong(f[1], 16));
		Address stop = toAddr(Long.parseUnsignedLong(f[2], 16));
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (int i = 0; i < 53; i++) {
				emu.writeRegister("r" + i, 0);
			}
			emu.writeRegister("tp", 0);
			emu.writeRegister("lr", 0);
			emu.writeRegister("sp", 0x8000);
			if (!f[3].equals("-")) {
				for (String kv : f[3].split(",")) {
					String[] p = kv.split("=");
					put(emu, p[0], new BigInteger(p[1], 16));
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			emu.setBreakpoint(stop);
			emu.run(start, null, monitor);
			if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT ||
				!emu.getExecutionAddress().equals(stop)) {
				return "did not reach " + stop + " (state " + emu.getEmulateExecutionState() +
					" at " + emu.getExecutionAddress() + ", " + emu.getLastError() + ")";
			}
			StringBuilder bad = new StringBuilder();
			for (String kv : f[4].split(",")) {
				String[] p = kv.split("=");
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got = get(emu, p[0]);
				if (!want.equals(got)) {
					bad.append(String.format(" %s=%x (want %x)", p[0], got, want));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}
}
