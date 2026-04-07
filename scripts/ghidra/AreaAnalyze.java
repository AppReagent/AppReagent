// AreaAnalyze.java — Ghidra headless script for AppReagent
// Extracts structured analysis data from binaries as JSON.
//
// Usage (via analyzeHeadless -postScript):
//   AreaAnalyze.java <output_path> <mode> [filter]
//
// Modes:
//   overview   — functions list + imports + exports + metadata
//   decompile  — decompiled C for all or filtered functions
//   strings    — defined strings with xref info
//   imports    — imports and exports detail
//   xrefs      — cross-references for a specific function (requires filter)
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

    private PrintWriter pw;
    private boolean firstEntry;
    private boolean firstSection = true;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: AreaAnalyze.java <output_path> <mode> [filter]");
            println("Modes: overview, decompile, strings, imports, xrefs, all");
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
            case "strings":
                writeStrings(filter);
                break;
            case "imports":
                writeImportsExports();
                break;
            case "xrefs":
                writeXrefs(filter);
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
        pw.println("    \"memory_size\": " + size);
        pw.print("  }");
    }

    private void writeFunctions(boolean decompile, String filter) throws Exception {
        sectionSep();
        pw.println("  \"functions\": [");
        firstEntry = true;

        String filterLower = filter.toLowerCase();

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
                if (!f.getName().toLowerCase().contains(filterLower)) continue;
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

            pw.print("    {\"name\": \"" + escJson(f.getName()) + "\"");
            pw.print(", \"library\": \"" + escJson(lib) + "\"");
            pw.print(", \"address\": \"" + f.getEntryPoint() + "\"}");
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

    private void writeXrefs(String funcName) {
        sectionSep();
        pw.println("  \"xrefs\": {");

        if (funcName.isEmpty()) {
            pw.println("    \"error\": \"xrefs mode requires a function name filter\"");
            pw.print("  }");
            return;
        }

        String nameLower = funcName.toLowerCase();
        Function target = null;
        FunctionIterator iter = currentProgram.getListing().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().toLowerCase().contains(nameLower)) {
                target = f;
                break;
            }
        }

        if (target == null) {
            pw.println("    \"error\": \"function not found: " + escJson(funcName) + "\"");
            pw.print("  }");
            return;
        }

        pw.println("    \"function\": \"" + escJson(target.getName()) + "\",");
        pw.println("    \"address\": \"" + target.getEntryPoint() + "\",");

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
