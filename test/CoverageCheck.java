// Every-entry decode test for TILE-Gx: every constructor of every table (slot tables x0..y2,
// operand tables, SPR names, JR flow) must be reachable. For each constructor the test overlays
// its pattern, then the pattern of a constructor that uses its table as an operand, and so on up
// to the root (outer patterns win), fills the remaining bits at random, decodes the bundle and
// records every constructor in the resulting tree. Constructors never reached are shadowed or
// unreachable; random differential fuzzing cannot see that when the reference also rejects them.
// Script args: <outfile> [tries-per-constructor (default 64)] [seed]
// Output: "unreached <table> <file>:<line> <print pieces>" lines, then a summary line.
//@category Testing

import java.io.PrintStream;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.pattern.PatternBlock;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;

public class CoverageCheck extends GhidraScript {

	private static final int LEN = 8;

	private static String key(Constructor c) {
		return c.getParent().getName() + " " + c.getSourceFile() + ":" + c.getLineno();
	}

	private static void collect(DecisionNode n, Map<Constructor, List<DisjointPattern>> pats) {
		if (n == null) {
			return;
		}
		List<DisjointPattern> p = n.getPatterns();
		List<Constructor> c = n.getConstructors();
		for (int i = 0; i < c.size(); i++) {
			pats.computeIfAbsent(c.get(i), k -> new ArrayList<>()).add(p.get(i));
		}
		for (DecisionNode ch : n.getChildren()) {
			collect(ch, pats);
		}
	}

	private static void walk(ConstructState s, Set<String> seen) {
		if (s == null) {
			return;
		}
		if (s.getConstructor() != null) {
			seen.add(key(s.getConstructor()));
		}
		for (int i = 0; i < s.getNumSubStates(); i++) {
			walk(s.getSubState(i), seen);
		}
	}

	private static void overlay(byte[] bytes, PatternBlock ib) {
		if (ib == null) {
			return;
		}
		int off = ib.getOffset();
		int[] m = ib.getMaskVector(), v = ib.getValueVector();
		for (int w = 0; w < m.length; w++) {
			for (int b = 0; b < 4; b++) {
				int i = off + w * 4 + b;
				if (i < 0 || i >= bytes.length) {
					continue;
				}
				int mb = (m[w] >>> (24 - 8 * b)) & 0xff;
				int vb = (v[w] >>> (24 - 8 * b)) & 0xff;
				bytes[i] = (byte) ((bytes[i] & ~mb) | (vb & mb));
			}
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		int tries = args.length > 1 ? Integer.parseInt(args[1]) : 64;
		Random rnd = new Random(args.length > 2 ? Long.parseLong(args[2]) : 1);
		SleighLanguage lang = (SleighLanguage) currentProgram.getLanguage();

		Map<Constructor, List<DisjointPattern>> pats = new HashMap<>();
		Map<String, Constructor> all = new TreeMap<>();
		Map<SubtableSymbol, List<Constructor>> users = new HashMap<>();
		for (Symbol sym : lang.getSymbolTable().getSymbolList()) {
			if (sym instanceof SubtableSymbol st) {
				collect(st.getDecisionNode(), pats);
				for (int i = 0; i < st.getNumConstructors(); i++) {
					Constructor c = st.getConstructor(i);
					all.put(key(c), c);
					for (int k = 0; k < c.getNumOperands(); k++) {
						TripleSymbol d = c.getOperand(k).getDefiningSymbol();
						if (d instanceof SubtableSymbol used) {
							users.computeIfAbsent(used, x -> new ArrayList<>()).add(c);
						}
					}
				}
			}
		}

		Set<String> seen = new HashSet<>();
		Address addr = currentProgram.getMinAddress();
		int decoded = 0, failed = 0;
		for (Constructor target : all.values()) {
			for (int t = 0; t < tries && !seen.contains(key(target)); t++) {
				byte[] bytes = new byte[LEN];
				rnd.nextBytes(bytes);
				if (t % 4 == 0) {
					Arrays.fill(bytes, t % 8 == 0 ? (byte) 0 : (byte) 0xff);
				}
				// chain of constructors from the target up to the root table
				Constructor c = target;
				int depth = 0;
				while (c != null && depth++ < 8) {
					List<DisjointPattern> cp = pats.get(c);
					if (cp != null && !cp.isEmpty()) {
						overlay(bytes, cp.get(rnd.nextInt(cp.size())).getInstructionBlock());
					}
					List<Constructor> u = users.get(c.getParent());
					c = u == null || u.isEmpty() ? null : u.get(rnd.nextInt(u.size()));
				}
				try {
					SleighInstructionPrototype proto = (SleighInstructionPrototype) lang.parse(
						new ByteMemBufferImpl(addr, bytes, lang.isBigEndian()), new ProcessorContextImpl(lang),
						false);
					walk(proto.getRootState(), seen);
					decoded++;
				}
				catch (Exception e) {
					failed++;
				}
			}
		}
		int unreached = 0;
		for (Map.Entry<String, Constructor> e : all.entrySet()) {
			if (!seen.contains(e.getKey())) {
				unreached++;
				out.println("unreached " + e.getKey() + " " +
					String.join("", e.getValue().getPrintPieces()).trim());
			}
		}
		out.printf("coverage: %d constructors, %d reached, %d unreached; %d decodes, %d rejected%n",
			all.size(), all.size() - unreached, unreached, decoded, failed);
		out.close();
	}
}
