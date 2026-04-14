// AreaAnalyze.java — Ghidra headless script for AppReagent
// Extracts structured analysis data from binaries as JSON.
//
// Usage (via analyzeHeadless -postScript):
//   AreaAnalyze.java <output_path> <mode> [filter]
//
// Modes:
//   overview   — functions list + imports + exports + metadata
//   decompile  — decompiled C for all or filtered functions
//   disasm     — assembly listing for a function or exact address
//   strings    — defined strings with xref info
//   imports    — imports and exports detail
//   xrefs      — cross-references for a specific function or data item (requires filter)
//   function_at — resolve an address to its containing function (requires filter)
//   data_at    — resolve an address to its containing defined data item (requires filter)
//   all        — everything (overview + decompile + strings + imports)
//
// @category AppReagent

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;

public class AreaAnalyze extends GhidraScript {
    private static final Map<String, Map<Integer, String>> IMPORT_ORDINAL_NAMES = createImportOrdinalNames();
    private static final int IMAGE_FILE_DLL = 0x2000;

    private PrintWriter pw;
    private boolean firstEntry;
    private boolean firstSection = true;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: AreaAnalyze.java <output_path> <mode> [filter]");
            println("Modes: overview, decompile, disasm, strings, imports, xrefs, function_at, data_at, all");
            return;
        }

        String outPath = args[0];
        String mode = args[1].toLowerCase();
        String filter = args.length > 2 ? args[2] : "";

        pw = new PrintWriter(new BufferedWriter(new FileWriter(outPath)));
        pw.println("{");
        firstSection = true;

        writeMetadata();

        switch (mode) {
            case "overview":
                writeFunctions(false, filter);
                writeImportsExports();
                break;
            case "decompile":
                writeFunctions(true, filter);
                break;
            case "disasm":
                writeDisassembly(filter);
                break;
            case "strings":
                writeStrings(filter);
                break;
            case "imports":
                writeImportsExports();
                break;
            case "xrefs":
                writeXrefs(filter);
                break;
            case "function_at":
                writeFunctionAt(filter);
                break;
            case "data_at":
                writeDataAt(filter);
                break;
            case "all":
                writeFunctions(true, filter);
                writeImportsExports();
                writeStrings("");
                break;
            default:
                sectionSep();
                pw.println("  \"error\": \"Unknown mode: " + escJson(mode) + "\"");
                break;
        }

        pw.println("\n}");
        pw.close();
        println("AreaAnalyze: wrote " + mode + " to " + outPath);
    }

    private void sectionSep() {
        if (!firstSection) pw.println(",");
        firstSection = false;
    }

    private void writeMetadata() {
        sectionSep();
        PeMetadata pe = parsePeMetadata();
        pw.println("  \"metadata\": {");
        pw.println("    \"name\": \"" + escJson(currentProgram.getName()) + "\",");
        pw.println("    \"language\": \"" + escJson(currentProgram.getLanguageID().toString()) + "\",");
        pw.println("    \"compiler\": \"" + escJson(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\",");
        pw.println("    \"image_base\": \"" + currentProgram.getImageBase() + "\",");
        pw.println("    \"executable_format\": \"" + escJson(currentProgram.getExecutableFormat()) + "\",");

        int funcCount = 0;
        FunctionIterator fi = currentProgram.getListing().getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcCount++; }
        pw.println("    \"function_count\": " + funcCount + ",");

        Memory mem = currentProgram.getMemory();
        long size = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            size += block.getSize();
        }
        pw.println("    \"memory_size\": " + size + (pe != null ? "," : ""));
        if (pe != null) {
            pw.println("    \"is_dll\": " + pe.isDll + ",");
            pw.println("    \"entry_point\": \"" + pe.entryPoint + "\",");
            pw.println("    \"entry_point_rva\": \"0x" + Long.toHexString(pe.entryPointRva).toUpperCase() + "\",");
            if (pe.entryFunction != null) {
                pw.println("    \"entry_function\": \"" + escJson(pe.entryFunction) + "\",");
                pw.println("    \"entry_signature\": \"" + escJson(pe.entrySignature) + "\",");
                pw.print("    \"entry_callees\": [");
                for (int i = 0; i < pe.entryCallees.size(); i++) {
                    if (i > 0) pw.print(", ");
                    FunctionRef ref = pe.entryCallees.get(i);
                    pw.print("{\"name\": \"" + escJson(ref.name) + "\", \"address\": \"" + ref.address + "\"}");
                }
                pw.println("],");
                if (pe.likelyDllMain != null) {
                    pw.println("    \"likely_dllmain\": {\"name\": \"" + escJson(pe.likelyDllMain.name)
                        + "\", \"address\": \"" + pe.likelyDllMain.address + "\"},");
                }
            }
            pw.print("    \"section_names\": [");
            for (int i = 0; i < pe.sectionNames.size(); i++) {
                if (i > 0) pw.print(", ");
                pw.print("\"" + escJson(pe.sectionNames.get(i)) + "\"");
            }
            pw.println("]");
        }
        pw.print("  }");
    }

    private static class PeMetadata {
        boolean isDll;
        String entryPoint;
        long entryPointRva;
        String entryFunction;
        String entrySignature;
        List<FunctionRef> entryCallees = new ArrayList<>();
        FunctionRef likelyDllMain;
        List<String> sectionNames = new ArrayList<>();
    }

    private static class FunctionRef {
        String name;
        String address;

        FunctionRef(String name, String address) {
            this.name = name;
            this.address = address;
        }
    }

    private PeMetadata parsePeMetadata() {
        if (!currentProgram.getExecutableFormat().contains("Portable Executable")) return null;
        try {
            Memory mem = currentProgram.getMemory();
            Address base = currentProgram.getImageBase();
            long peOffset = readU32(mem, base, 0x3c);
            if (readU32(mem, base, peOffset) != 0x00004550L) return null;

            int numberOfSections = (int) readU16(mem, base, peOffset + 6);
            int characteristics = (int) readU16(mem, base, peOffset + 22);
            long optionalOffset = peOffset + 24;
            long entryPointRva = readU32(mem, base, optionalOffset + 16);
            Address entryPoint = base.add(entryPointRva);

            PeMetadata pe = new PeMetadata();
            pe.isDll = (characteristics & IMAGE_FILE_DLL) != 0;
            pe.entryPoint = entryPoint.toString();
            pe.entryPointRva = entryPointRva;

            Function entryFunction = getFunctionContaining(entryPoint);
            if (entryFunction == null) entryFunction = getFunctionAt(entryPoint);
            if (entryFunction != null) {
                pe.entryFunction = entryFunction.getName();
                pe.entrySignature = entryFunction.getPrototypeString(false, false);
                Set<Function> entryCallees = entryFunction.getCalledFunctions(monitor);
                for (Function callee : entryCallees) {
                    pe.entryCallees.add(new FunctionRef(callee.getName(), callee.getEntryPoint().toString()));
                }
                pe.likelyDllMain = findLikelyDllMain(entryPoint, entryCallees);
            }

            int optionalSize = (int) readU16(mem, base, peOffset + 20);
            long sectionOffset = optionalOffset + optionalSize;
            int maxSections = Math.min(numberOfSections, 32);
            for (int i = 0; i < maxSections; i++) {
                String name = readAscii(mem, base, sectionOffset + (long) i * 40, 8);
                if (!name.isEmpty()) pe.sectionNames.add(name);
            }
            return pe;
        } catch (Exception e) {
            return null;
        }
    }

    private int readU8(Memory mem, Address base, long offset) throws Exception {
        return mem.getByte(base.add(offset)) & 0xff;
    }

    private long readU16(Memory mem, Address base, long offset) throws Exception {
        return (long) readU8(mem, base, offset)
             | ((long) readU8(mem, base, offset + 1) << 8);
    }

    private long readU32(Memory mem, Address base, long offset) throws Exception {
        return (long) readU8(mem, base, offset)
             | ((long) readU8(mem, base, offset + 1) << 8)
             | ((long) readU8(mem, base, offset + 2) << 16)
             | ((long) readU8(mem, base, offset + 3) << 24);
    }

    private String readAscii(Memory mem, Address base, long offset, int maxLen) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxLen; i++) {
            int b = readU8(mem, base, offset + i);
            if (b == 0) break;
            sb.append((char) b);
        }
        return sb.toString().trim();
    }

    private FunctionRef findLikelyDllMain(Address entryPoint, Set<Function> callees) {
        if (callees == null || callees.isEmpty()) return null;
        Function best = null;
        long bestDistance = 0;
        for (Function callee : callees) {
            if (callee == null || callee.isThunk()) continue;
            String name = callee.getName();
            if (name == null) continue;
            if (name.startsWith("__") || name.startsWith("Unwind@") || name.startsWith("Catch@")) continue;
            long distance = Math.abs(callee.getEntryPoint().getOffset() - entryPoint.getOffset());
            if (distance <= 0x100) continue;
            if (best == null || distance > bestDistance) {
                best = callee;
                bestDistance = distance;
            }
        }
        if (best == null) return null;
        return new FunctionRef(best.getName(), best.getEntryPoint().toString());
    }

    // Resolve a filter string to a specific Function. Supports both name
    // substrings ("gethostbyname") and hex addresses ("0x10001656" or
    // "10001656") — when the filter looks like an address, the function
    // containing that address is returned.
    private Function resolveFilterFunction(String filter) {
        if (filter == null || filter.isEmpty()) return null;
        Address addr = parseAddressMaybe(filter);
        if (addr != null) {
            Function f = getFunctionContaining(addr);
            if (f != null) return f;
            f = getFunctionAt(addr);
            return f;
        }
        String nameLower = filter.toLowerCase();
        FunctionIterator iter = currentProgram.getListing().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().toLowerCase().contains(nameLower)) return f;
        }
        return null;
    }

    // Try to parse a filter string as a hex address. Returns null if it
    // doesn't look like a hex number we can resolve against the program's
    // default address space.
    private Address parseAddressMaybe(String filter) {
        if (filter == null || filter.isEmpty()) return null;
        String s = filter.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        if (s.isEmpty() || s.length() > 16) return null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean isHex = (c >= '0' && c <= '9')
                         || (c >= 'a' && c <= 'f')
                         || (c >= 'A' && c <= 'F');
            if (!isHex) return null;
        }
        try {
            long val = Long.parseUnsignedLong(s, 16);
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val);
        } catch (Exception e) {
            return null;
        }
    }

    private void writeFunctions(boolean decompile, String filter) throws Exception {
        sectionSep();
        pw.println("  \"functions\": [");
        firstEntry = true;

        String filterLower = filter.toLowerCase();
        Function targeted = filter.isEmpty() ? null : resolveFilterFunction(filter);
        boolean addressFilter = !filter.isEmpty() && parseAddressMaybe(filter) != null;

        DecompInterface decomp = null;
        if (decompile) {
            decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
        }

        int count = 0;
        int maxFuncs = decompile ? 200 : 500;

        FunctionIterator iter = currentProgram.getListing().getFunctions(true);
        while (iter.hasNext() && !monitor.isCancelled() && count < maxFuncs) {
            Function f = iter.next();

            if (!filterLower.isEmpty()) {
                if (addressFilter) {
                    // address-based: only emit the resolved function
                    if (targeted == null || !f.getEntryPoint().equals(targeted.getEntryPoint())) continue;
                } else {
                    if (!f.getName().toLowerCase().contains(filterLower)) continue;
                }
            }

            if (!decompile && f.isThunk() && filterLower.isEmpty()) continue;

            if (!firstEntry) pw.println(",");
            firstEntry = false;

            pw.print("    {\"name\": \"" + escJson(f.getName()) + "\"");
            pw.print(", \"address\": \"" + f.getEntryPoint() + "\"");
            pw.print(", \"signature\": \"" + escJson(f.getPrototypeString(false, false)) + "\"");
            pw.print(", \"size\": " + f.getBody().getNumAddresses());
            pw.print(", \"is_thunk\": " + f.isThunk());
            pw.print(", \"calling_convention\": \"" + escJson(f.getCallingConventionName()) + "\"");

            Reference[] refsTo = getReferencesTo(f.getEntryPoint());
            int callerCount = 0;
            for (Reference r : refsTo) {
                if (r.getReferenceType().isCall()) callerCount++;
            }
            pw.print(", \"caller_count\": " + callerCount);

            Set<Function> callees = f.getCalledFunctions(monitor);
            pw.print(", \"callee_count\": " + callees.size());

            if (decompile && decomp != null) {
                DecompileResults results = decomp.decompileFunction(f, 30, monitor);
                String code = "";
                if (results.decompileCompleted()) {
                    DecompiledFunction df = results.getDecompiledFunction();
                    if (df != null) code = df.getC();
                }
                if (code.length() > 8000) {
                    code = code.substring(0, 8000) + "\n/* ... truncated ... */";
                }
                pw.print(", \"decompiled\": \"" + escJson(code) + "\"");
            }

            pw.print("}");
            count++;
        }

        if (decomp != null) decomp.dispose();

        pw.print("\n  ]");
    }

    private void writeImportsExports() {
        sectionSep();
        pw.println("  \"imports\": [");
        firstEntry = true;

        FunctionIterator extFuncs = currentProgram.getListing().getExternalFunctions();
        int count = 0;
        while (extFuncs.hasNext() && count < 500) {
            Function f = extFuncs.next();
            ExternalLocation extLoc = f.getExternalLocation();

            if (!firstEntry) pw.println(",");
            firstEntry = false;

            String lib = (extLoc != null && extLoc.getLibraryName() != null)
                ? extLoc.getLibraryName() : "";
            String originalName = f.getName();
            Integer ordinal = extractOrdinal(originalName);
            String resolvedName = resolveImportName(lib, originalName);
            Reference[] refsTo = getReferencesTo(f.getEntryPoint());
            Set<String> refFuncs = new LinkedHashSet<>();
            int callerCount = 0;
            for (Reference ref : refsTo) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) refFuncs.add(caller.getName());
                if (ref.getReferenceType().isCall()) callerCount++;
            }

            pw.print("    {\"name\": \"" + escJson(resolvedName) + "\"");
            pw.print(", \"library\": \"" + escJson(lib) + "\"");
            pw.print(", \"address\": \"" + f.getEntryPoint() + "\"");
            if (!resolvedName.equals(originalName)) {
                pw.print(", \"original_name\": \"" + escJson(originalName) + "\"");
            }
            if (ordinal != null) {
                pw.print(", \"ordinal\": " + ordinal);
            }
            pw.print(", \"caller_count\": " + callerCount);
            if (!refFuncs.isEmpty()) {
                pw.print(", \"referenced_by\": [");
                boolean first = true;
                int shown = 0;
                for (String fn : refFuncs) {
                    if (shown++ >= 10) break;
                    if (!first) pw.print(", ");
                    first = false;
                    pw.print("\"" + escJson(fn) + "\"");
                }
                pw.print("]");
            }
            pw.print("}");
            count++;
        }
        pw.print("\n  ]");

        sectionSep();
        pw.println("  \"exports\": [");
        firstEntry = true;
        count = 0;

        SymbolTable symTable = currentProgram.getSymbolTable();
        AddressIterator exportAddrs = symTable.getExternalEntryPointIterator();
        while (exportAddrs.hasNext() && count < 500) {
            Address addr = exportAddrs.next();
            Symbol sym = symTable.getPrimarySymbol(addr);
            if (sym == null) continue;

            if (!firstEntry) pw.println(",");
            firstEntry = false;

            Function f = getFunctionAt(addr);
            String sig = (f != null) ? f.getPrototypeString(false, false) : "";

            pw.print("    {\"name\": \"" + escJson(sym.getName()) + "\"");
            pw.print(", \"address\": \"" + addr + "\"");
            pw.print(", \"signature\": \"" + escJson(sig) + "\"}");
            count++;
        }
        pw.print("\n  ]");
    }

    private void writeStrings(String filter) {
        sectionSep();
        pw.println("  \"strings\": [");
        firstEntry = true;

        String filterLower = filter.toLowerCase();
        int count = 0;

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled() && count < 1000) {
            Data data = dataIter.next();
            String typeName = data.getDataType().getName().toLowerCase();

            if (!typeName.contains("string") && !typeName.contains("unicode")) continue;

            Object value = data.getValue();
            if (value == null) continue;
            String strVal = value.toString();
            if (strVal.length() < 4) continue;

            if (!filterLower.isEmpty() && !strVal.toLowerCase().contains(filterLower)) continue;

            Reference[] refs = getReferencesTo(data.getAddress());

            Set<String> refFuncs = new LinkedHashSet<>();
            for (Reference ref : refs) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) refFuncs.add(caller.getName());
            }

            if (!firstEntry) pw.println(",");
            firstEntry = false;

            pw.print("    {\"address\": \"" + data.getAddress() + "\"");
            pw.print(", \"value\": \"" + escJson(strVal) + "\"");
            pw.print(", \"type\": \"" + escJson(data.getDataType().getName()) + "\"");
            pw.print(", \"xref_count\": " + refs.length);

            if (!refFuncs.isEmpty()) {
                pw.print(", \"referenced_by\": [");
                boolean first = true;
                int shown = 0;
                for (String fn : refFuncs) {
                    if (shown++ >= 10) break;
                    if (!first) pw.print(", ");
                    first = false;
                    pw.print("\"" + escJson(fn) + "\"");
                }
                pw.print("]");
            }

            pw.print("}");
            count++;
        }
        pw.print("\n  ]");
    }

    private String formatInstruction(Instruction instr) {
        return instr.toString();
    }

    private void writeDisassembly(String filter) {
        sectionSep();
        pw.println("  \"disassembly\": {");

        Listing listing = currentProgram.getListing();
        Address requestedAddr = parseAddressMaybe(filter);
        Function target = (filter == null || filter.isEmpty()) ? null : resolveFilterFunction(filter);

        if ((filter == null || filter.isEmpty()) && target == null) {
            FunctionIterator iter = listing.getFunctions(true);
            if (iter.hasNext()) target = iter.next();
        }

        Instruction requestedInstr = null;
        if (requestedAddr != null) {
            requestedInstr = listing.getInstructionContaining(requestedAddr);
            if (requestedInstr == null) requestedInstr = listing.getInstructionAt(requestedAddr);
        }

        if (target == null && requestedInstr == null) {
            pw.println("    \"error\": \"disasm mode requires a function name or code address filter\"");
            pw.print("  }");
            return;
        }

        List<Instruction> selected = new ArrayList<>();
        if (target != null) {
            List<Instruction> all = new ArrayList<>();
            InstructionIterator iter = listing.getInstructions(target.getBody(), true);
            while (iter.hasNext() && !monitor.isCancelled()) {
                all.add(iter.next());
            }

            int start = 0;
            int end = all.size();
            if (requestedInstr != null) {
                int hit = -1;
                for (int i = 0; i < all.size(); i++) {
                    if (all.get(i).getAddress().equals(requestedInstr.getAddress())) {
                        hit = i;
                        break;
                    }
                }
                if (hit >= 0) {
                    start = Math.max(0, hit - 20);
                    end = Math.min(all.size(), hit + 21);
                } else {
                    end = Math.min(all.size(), 60);
                }
            } else {
                end = Math.min(all.size(), 120);
            }
            for (int i = start; i < end; i++) selected.add(all.get(i));

            pw.println("    \"kind\": \"function\",");
            pw.println("    \"function\": \"" + escJson(target.getName()) + "\",");
            pw.println("    \"address\": \"" + target.getEntryPoint() + "\",");
            pw.println("    \"signature\": \"" + escJson(target.getPrototypeString(false, false)) + "\",");
            pw.println("    \"function_instruction_count\": " + all.size() + ",");
            if (requestedAddr != null) {
                pw.println("    \"requested_address\": \"" + requestedAddr + "\",");
                pw.println("    \"offset_from_entry\": " + requestedAddr.subtract(target.getEntryPoint()) + ",");
            }
            if (!all.isEmpty() && selected.size() < all.size()) {
                pw.println("    \"window_start\": \"" + selected.get(0).getAddress() + "\",");
                pw.println("    \"window_end\": \"" + selected.get(selected.size() - 1).getAddress() + "\",");
            }
        } else {
            selected.add(requestedInstr);
            Instruction before = requestedInstr;
            for (int i = 0; i < 10; i++) {
                before = listing.getInstructionBefore(before.getAddress());
                if (before == null) break;
                selected.add(0, before);
            }
            Instruction after = requestedInstr;
            for (int i = 0; i < 10; i++) {
                after = listing.getInstructionAfter(after.getAddress());
                if (after == null) break;
                selected.add(after);
            }

            pw.println("    \"kind\": \"window\",");
            pw.println("    \"requested_address\": \"" + requestedAddr + "\",");
            pw.println("    \"window_start\": \"" + selected.get(0).getAddress() + "\",");
            pw.println("    \"window_end\": \"" + selected.get(selected.size() - 1).getAddress() + "\",");
        }

        pw.println("    \"instruction_count\": " + selected.size() + ",");
        pw.println("    \"instructions\": [");
        boolean first = true;
        for (Instruction instr : selected) {
            if (!first) pw.println(",");
            first = false;
            pw.print("      {\"address\": \"" + instr.getAddress() + "\"");
            pw.print(", \"text\": \"" + escJson(formatInstruction(instr)) + "\"");
            pw.print(", \"flow_type\": \"" + escJson(instr.getFlowType().toString()) + "\"");
            if (requestedInstr != null && instr.getAddress().equals(requestedInstr.getAddress())) {
                pw.print(", \"is_target\": true");
            }
            pw.print("}");
        }
        pw.println("\n    ]");
        pw.print("  }");
    }

    private Data resolveFilterData(String filter) {
        Address addr = parseAddressMaybe(filter);
        if (addr == null) return null;
        Data data = currentProgram.getListing().getDefinedDataContaining(addr);
        if (data != null) return data;
        return currentProgram.getListing().getDataAt(addr);
    }

    private static Map<String, Map<Integer, String>> createImportOrdinalNames() {
        Map<String, Map<Integer, String>> libs = new HashMap<>();

        Map<Integer, String> ws2 = new HashMap<>();
        ws2.put(3, "closesocket");
        ws2.put(4, "connect");
        ws2.put(9, "htons");
        ws2.put(11, "inet_addr");
        ws2.put(12, "inet_ntoa");
        ws2.put(15, "ntohs");
        ws2.put(16, "recv");
        ws2.put(18, "select");
        ws2.put(19, "send");
        ws2.put(21, "setsockopt");
        ws2.put(23, "socket");
        ws2.put(52, "gethostbyname");
        ws2.put(111, "WSAGetLastError");
        ws2.put(115, "WSAStartup");
        ws2.put(116, "WSACleanup");
        libs.put("ws2_32.dll", ws2);

        return libs;
    }

    private Integer extractOrdinal(String name) {
        if (name == null) return null;
        String prefix = "Ordinal_";
        if (!name.startsWith(prefix)) return null;
        try {
            return Integer.parseInt(name.substring(prefix.length()));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String resolveImportName(String library, String name) {
        Integer ordinal = extractOrdinal(name);
        if (ordinal == null || library == null) return name;
        Map<Integer, String> byOrdinal = IMPORT_ORDINAL_NAMES.get(library.toLowerCase());
        if (byOrdinal == null) return name;
        String resolved = byOrdinal.get(ordinal);
        return resolved != null ? resolved : name;
    }

    private void writeFunctionJson(Function f, Address requestedAddr, boolean includeDecompile) throws Exception {
        pw.print("    \"name\": \"" + escJson(f.getName()) + "\"");
        pw.print(",\n    \"address\": \"" + f.getEntryPoint() + "\"");
        pw.print(",\n    \"signature\": \"" + escJson(f.getPrototypeString(false, false)) + "\"");
        pw.print(",\n    \"size\": " + f.getBody().getNumAddresses());
        pw.print(",\n    \"is_thunk\": " + f.isThunk());
        pw.print(",\n    \"calling_convention\": \"" + escJson(f.getCallingConventionName()) + "\"");

        Reference[] refsTo = getReferencesTo(f.getEntryPoint());
        int callerCount = 0;
        for (Reference r : refsTo) {
            if (r.getReferenceType().isCall()) callerCount++;
        }
        pw.print(",\n    \"caller_count\": " + callerCount);

        Set<Function> callees = f.getCalledFunctions(monitor);
        pw.print(",\n    \"callee_count\": " + callees.size());

        if (requestedAddr != null) {
            long offset = requestedAddr.subtract(f.getEntryPoint());
            pw.print(",\n    \"requested_address\": \"" + requestedAddr + "\"");
            pw.print(",\n    \"offset_from_entry\": " + offset);
        }

        if (includeDecompile) {
            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(currentProgram);
                DecompileResults results = decomp.decompileFunction(f, 30, monitor);
                String code = "";
                if (results.decompileCompleted()) {
                    DecompiledFunction df = results.getDecompiledFunction();
                    if (df != null) code = df.getC();
                }
                if (code.length() > 8000) {
                    code = code.substring(0, 8000) + "\n/* ... truncated ... */";
                }
                pw.print(",\n    \"decompiled\": \"" + escJson(code) + "\"");
            } finally {
                decomp.dispose();
            }
        }
    }

    private void writeDataJson(Data data, Address requestedAddr) {
        Address min = data.getAddress();
        Address max = data.getMaxAddress();
        pw.print("    \"address\": \"" + min + "\"");
        pw.print(",\n    \"max_address\": \"" + max + "\"");
        pw.print(",\n    \"data_type\": \"" + escJson(data.getDataType().getName()) + "\"");
        pw.print(",\n    \"length\": " + data.getLength());

        if (requestedAddr != null) {
            long offset = requestedAddr.subtract(min);
            pw.print(",\n    \"requested_address\": \"" + requestedAddr + "\"");
            pw.print(",\n    \"offset_from_start\": " + offset);
        }

        Object value = data.getValue();
        if (value != null) {
            String strVal = value.toString();
            if (strVal.length() > 2000) {
                strVal = strVal.substring(0, 2000) + "... (truncated)";
            }
            pw.print(",\n    \"value\": \"" + escJson(strVal) + "\"");
        }

        MemoryBlock block = currentProgram.getMemory().getBlock(min);
        if (block != null) {
            pw.print(",\n    \"memory_block\": \"" + escJson(block.getName()) + "\"");
        }

        Reference[] refs = getReferencesTo(min);
        pw.print(",\n    \"xref_count\": " + refs.length);
        if (refs.length > 0) {
            pw.print(",\n    \"references\": [");
            boolean firstRef = true;
            int shown = 0;
            for (Reference ref : refs) {
                if (shown++ >= 50) break;
                if (!firstRef) pw.print(", ");
                firstRef = false;
                Function caller = getFunctionContaining(ref.getFromAddress());
                pw.print("{\"from\": \"" + ref.getFromAddress() + "\"");
                pw.print(", \"function\": \"" + escJson(caller != null ? caller.getName() : "unknown") + "\"");
                pw.print(", \"type\": \"" + escJson(ref.getReferenceType().getName()) + "\"}");
            }
            pw.print("]");
        }
    }

    private void writeFunctionAt(String filter) throws Exception {
        sectionSep();
        pw.println("  \"function_at\": {");

        if (filter.isEmpty()) {
            pw.println("    \"error\": \"function_at mode requires a hex address filter\"");
            pw.print("  }");
            return;
        }

        Address addr = parseAddressMaybe(filter);
        if (addr == null) {
            pw.println("    \"error\": \"invalid address: " + escJson(filter) + "\"");
            pw.print("  }");
            return;
        }

        Function target = getFunctionContaining(addr);
        if (target == null) {
            target = getFunctionAt(addr);
        }

        if (target == null) {
            pw.println("    \"error\": \"no function contains address: " + escJson(filter) + "\"");
            pw.print("  }");
            return;
        }

        writeFunctionJson(target, addr, false);
        pw.print("\n  }");
    }

    private void writeDataAt(String filter) {
        sectionSep();
        pw.println("  \"data_at\": {");

        if (filter.isEmpty()) {
            pw.println("    \"error\": \"data_at mode requires a hex address filter\"");
            pw.print("  }");
            return;
        }

        Address addr = parseAddressMaybe(filter);
        if (addr == null) {
            pw.println("    \"error\": \"invalid address: " + escJson(filter) + "\"");
            pw.print("  }");
            return;
        }

        Data data = resolveFilterData(filter);
        if (data == null) {
            pw.println("    \"error\": \"no defined data contains address: " + escJson(filter) + "\"");
            pw.print("  }");
            return;
        }

        writeDataJson(data, addr);
        pw.print("\n  }");
    }

    private void writeXrefs(String funcName) throws Exception {
        sectionSep();
        pw.println("  \"xrefs\": {");

        if (funcName.isEmpty()) {
            pw.println("    \"error\": \"xrefs mode requires a function name or hex address filter\"");
            pw.print("  }");
            return;
        }

        Address requestedAddr = parseAddressMaybe(funcName);
        Function target = resolveFilterFunction(funcName);
        Data targetData = target == null ? resolveFilterData(funcName) : null;

        if (target == null && targetData == null) {
            pw.println("    \"error\": \"symbol not found: " + escJson(funcName) + "\"");
            pw.print("  }");
            return;
        }

        if (requestedAddr != null) {
            pw.println("    \"requested_address\": \"" + requestedAddr + "\",");
        }

        if (target != null) {
            pw.println("    \"kind\": \"function\",");
            pw.println("    \"function\": \"" + escJson(target.getName()) + "\",");
            pw.println("    \"address\": \"" + target.getEntryPoint() + "\",");
            if (requestedAddr != null) {
                pw.println("    \"offset_from_entry\": " + requestedAddr.subtract(target.getEntryPoint()) + ",");
            }

            pw.println("    \"callers\": [");
            Reference[] refsTo = getReferencesTo(target.getEntryPoint());
            firstEntry = true;
            for (Reference ref : refsTo) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (!firstEntry) pw.println(",");
                firstEntry = false;

                pw.print("      {\"from\": \"" + ref.getFromAddress() + "\"");
                pw.print(", \"function\": \"" + escJson(caller != null ? caller.getName() : "unknown") + "\"");
                pw.print(", \"type\": \"" + escJson(ref.getReferenceType().getName()) + "\"}");
            }
            pw.println("\n    ],");

            pw.println("    \"callees\": [");
            firstEntry = true;
            Set<Function> callees = target.getCalledFunctions(monitor);
            for (Function callee : callees) {
                if (!firstEntry) pw.println(",");
                firstEntry = false;

                pw.print("      {\"name\": \"" + escJson(callee.getName()) + "\"");
                pw.print(", \"address\": \"" + callee.getEntryPoint() + "\"}");
            }
            pw.println("\n    ]");
        } else {
            pw.println("    \"kind\": \"data\",");
            writeDataJson(targetData, requestedAddr);
            pw.println(",");
            pw.println("    \"callees\": []");
        }

        pw.print("  }");
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "")
                .replace("\t", "\\t")
                .replace("\b", "\\b")
                .replace("\f", "\\f");
    }
}
