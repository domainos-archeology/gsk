package ghidrahttp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.GoToService;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.framework.model.EventType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;

/**
 * HTTP Server that exposes Ghidra functionality through a REST-like API.
 */
public class GhidraHTTPServer {

    private final int port;
    private final PluginTool tool;
    private Program program;
    private HttpServer server;
    private boolean running = false;

    // Change tracking
    private final Queue<ChangeRecord> changeHistory = new ConcurrentLinkedQueue<>();
    private DomainObjectListener changeListener;

    public GhidraHTTPServer(int port, PluginTool tool, Program program) {
        this.port = port;
        this.tool = tool;
        this.program = program;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

        // Register all endpoints
        registerEndpoints();

        server.start();
        running = true;
        Msg.info(this, "GhidraHTTP server started on port " + port);

        // Start change tracking
        if (program != null) {
            setupChangeListener();
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            running = false;
            Msg.info(this, "GhidraHTTP server stopped");
        }
        if (changeListener != null && program != null) {
            program.removeListener(changeListener);
        }
    }

    public boolean isRunning() {
        return running;
    }

    public void setProgram(Program program) {
        // Remove listener from old program
        if (this.program != null && changeListener != null) {
            this.program.removeListener(changeListener);
        }

        this.program = program;

        // Add listener to new program
        if (program != null) {
            setupChangeListener();
        }
    }

    private void setupChangeListener() {
        changeListener = new DomainObjectListener() {
            @Override
            public void domainObjectChanged(DomainObjectChangedEvent ev) {
                for (int i = 0; i < ev.numRecords(); i++) {
                    DomainObjectChangeRecord record = ev.getChangeRecord(i);
                    processChangeRecord(record);
                }
            }
        };
        program.addListener(changeListener);
    }

    private void processChangeRecord(DomainObjectChangeRecord record) {
        long timestamp = System.currentTimeMillis();
        EventType eventType = record.getEventType();
        String changeType = eventType.toString().toLowerCase();
        String details = "";
        String address = "";

        Object oldValue = record.getOldValue();
        Object newValue = record.getNewValue();
        if (oldValue != null || newValue != null) {
            details = String.format("Old: %s, New: %s",
                oldValue != null ? oldValue.toString() : "null",
                newValue != null ? newValue.toString() : "null");
        }

        ChangeRecord cr = new ChangeRecord(timestamp, changeType, address, details);
        changeHistory.add(cr);

        // Keep only last 1000 changes
        while (changeHistory.size() > 1000) {
            changeHistory.poll();
        }
    }

    private void registerEndpoints() {
        // GET endpoints
        server.createContext("/decompile_function", new DecompileFunctionHandler());
        server.createContext("/disassemble_function", new DisassembleFunctionHandler());
        server.createContext("/get_function_by_address", new GetFunctionByAddressHandler());
        server.createContext("/get_current_function", new GetCurrentFunctionHandler());
        server.createContext("/get_current_address", new GetCurrentAddressHandler());
        server.createContext("/list_functions", new ListFunctionsHandler());
        server.createContext("/xrefs_to", new XrefsToHandler());
        server.createContext("/xrefs_from", new XrefsFromHandler());
        server.createContext("/strings", new StringsHandler());
        server.createContext("/searchFunctions", new SearchFunctionsHandler());
        server.createContext("/changes_since", new ChangesSinceHandler());

        // Type endpoints
        server.createContext("/list_types", new ListTypesHandler());
        server.createContext("/get_type", new GetTypeHandler());
        server.createContext("/search_types", new SearchTypesHandler());
        server.createContext("/create_type", new CreateTypeHandler());
        server.createContext("/update_type", new UpdateTypeHandler());

        // Equate endpoints
        server.createContext("/list_equates", new ListEquatesHandler());
        server.createContext("/get_equate", new GetEquateHandler());
        server.createContext("/set_equate", new SetEquateHandler());
        server.createContext("/delete_equate", new DeleteEquateHandler());

        // Label endpoints
        server.createContext("/list_labels", new ListLabelsHandler());
        server.createContext("/set_label", new SetLabelHandler());
        server.createContext("/delete_label", new DeleteLabelHandler());

        // Symbol tree endpoints (namespaces, classes, imports, exports)
        server.createContext("/list_namespaces", new ListNamespacesHandler());
        server.createContext("/list_classes", new ListClassesHandler());
        server.createContext("/list_imports", new ListImportsHandler());
        server.createContext("/list_exports", new ListExportsHandler());

        // Memory read endpoint
        server.createContext("/read_memory", new ReadMemoryHandler());

        // Data type assignment endpoints
        server.createContext("/get_data", new GetDataHandler());
        server.createContext("/set_data_type", new SetDataTypeHandler());
        server.createContext("/clear_data", new ClearDataHandler());

        // Program info and memory map endpoints
        server.createContext("/program_info", new ProgramInfoHandler());
        server.createContext("/list_memory_blocks", new ListMemoryBlocksHandler());

        // Bookmark endpoints
        server.createContext("/list_bookmarks", new ListBookmarksHandler());
        server.createContext("/set_bookmark", new SetBookmarkHandler());
        server.createContext("/delete_bookmark", new DeleteBookmarkHandler());

        // POST endpoints
        server.createContext("/set_function_prototype", new SetFunctionPrototypeHandler());
        server.createContext("/rename_function_by_address", new RenameFunctionHandler());
        server.createContext("/set_local_variable_type", new SetLocalVariableTypeHandler());
        server.createContext("/set_decompiler_comment", new SetDecompilerCommentHandler());
        server.createContext("/set_disassembly_comment", new SetDisassemblyCommentHandler());

        // Health check
        server.createContext("/health", exchange -> {
            String response = "OK";
            sendResponse(exchange, 200, response);
        });
    }

    // Utility methods
    private Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }
        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            if (pair.length == 2) {
                params.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                          URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
            } else if (pair.length == 1) {
                params.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8), "");
            }
        }
        return params;
    }

    private Map<String, String> parseFormData(HttpExchange exchange) throws IOException {
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr);
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        return parseQueryString(sb.toString());
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
        sendResponse(exchange, statusCode, "Error: " + message);
    }

    private Address parseAddress(String addressStr) {
        if (program == null) {
            return null;
        }
        AddressFactory factory = program.getAddressFactory();
        try {
            // Try parsing as hex with or without 0x prefix
            String cleanAddr = addressStr.toLowerCase().startsWith("0x")
                ? addressStr.substring(2)
                : addressStr;
            return factory.getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(cleanAddr, 16));
        } catch (NumberFormatException e) {
            // Try parsing directly (might be a named address)
            return factory.getAddress(addressStr);
        }
    }

    private String decompileFunction(Function function) {
        if (function == null) {
            return "Function not found";
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            } else {
                return "Decompilation failed: " + results.getErrorMessage();
            }
        } finally {
            decompiler.dispose();
        }
    }

    private String disassembleFunction(Function function) {
        if (function == null) {
            return "Function not found";
        }

        StringBuilder sb = new StringBuilder();
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

        sb.append(String.format("; Function: %s\n", function.getName()));
        sb.append(String.format("; Entry: %s\n", function.getEntryPoint()));
        sb.append(String.format("; Size: %d bytes\n\n", function.getBody().getNumAddresses()));

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(String.format("%s    %s\n", instr.getAddress(), instr.toString()));
        }

        return sb.toString();
    }

    private String formatFunction(Function function) {
        if (function == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(function.getName()).append("\n");
        sb.append("Entry: ").append(function.getEntryPoint()).append("\n");
        sb.append("Signature: ").append(function.getSignature().getPrototypeString()).append("\n");
        sb.append("Size: ").append(function.getBody().getNumAddresses()).append(" bytes\n");
        sb.append("Calling Convention: ").append(function.getCallingConventionName()).append("\n");
        return sb.toString();
    }

    // Handler classes for each endpoint

    private class DecompileFunctionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String addressStr = params.get("address");
            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Function function = program.getFunctionManager().getFunctionContaining(address);
            String result = decompileFunction(function);
            sendResponse(exchange, 200, result);
        }
    }

    private class DisassembleFunctionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String addressStr = params.get("address");
            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Function function = program.getFunctionManager().getFunctionContaining(address);
            String result = disassembleFunction(function);
            sendResponse(exchange, 200, result);
        }
    }

    private class GetFunctionByAddressHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String addressStr = params.get("address");
            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                sendError(exchange, 404, "No function found at address: " + addressStr);
                return;
            }
            sendResponse(exchange, 200, formatFunction(function));
        }
    }

    private class GetCurrentFunctionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            GoToService goToService = tool.getService(GoToService.class);
            if (goToService == null) {
                sendError(exchange, 503, "GoTo service not available");
                return;
            }

            ProgramLocation location = goToService.getDefaultNavigatable().getLocation();
            if (location == null) {
                sendError(exchange, 404, "No current location");
                return;
            }

            Address address = location.getAddress();
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                sendError(exchange, 404, "No function at current location");
                return;
            }
            sendResponse(exchange, 200, formatFunction(function));
        }
    }

    private class GetCurrentAddressHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            GoToService goToService = tool.getService(GoToService.class);
            if (goToService == null) {
                sendError(exchange, 503, "GoTo service not available");
                return;
            }

            ProgramLocation location = goToService.getDefaultNavigatable().getLocation();
            if (location == null) {
                sendError(exchange, 404, "No current location");
                return;
            }

            sendResponse(exchange, 200, location.getAddress().toString());
        }
    }

    private class ListFunctionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            StringBuilder sb = new StringBuilder();
            FunctionManager fm = program.getFunctionManager();
            FunctionIterator functions = fm.getFunctions(true);

            while (functions.hasNext()) {
                Function f = functions.next();
                sb.append(String.format("%s\t%s\n", f.getEntryPoint(), f.getName()));
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class XrefsToHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String addressStr = params.get("address");
            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            int limit = 100;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            StringBuilder sb = new StringBuilder();
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refs = refMgr.getReferencesTo(address);

            int count = 0;
            while (refs.hasNext() && count < limit) {
                Reference ref = refs.next();
                sb.append(String.format("%s -> %s (%s)\n",
                    ref.getFromAddress(),
                    ref.getToAddress(),
                    ref.getReferenceType().getName()));
                count++;
            }

            if (count == 0) {
                sb.append("No references found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class XrefsFromHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String addressStr = params.get("address");
            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            int limit = 100;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            StringBuilder sb = new StringBuilder();
            ReferenceManager refMgr = program.getReferenceManager();
            Reference[] refs = refMgr.getReferencesFrom(address);

            int count = 0;
            for (Reference ref : refs) {
                if (count >= limit) break;
                sb.append(String.format("%s -> %s (%s)\n",
                    ref.getFromAddress(),
                    ref.getToAddress(),
                    ref.getReferenceType().getName()));
                count++;
            }

            if (count == 0) {
                sb.append("No references found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class StringsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            int limit = 100;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            String filter = params.get("filter");

            StringBuilder sb = new StringBuilder();
            DataIterator dataIterator = program.getListing().getDefinedData(true);

            int count = 0;
            while (dataIterator.hasNext() && count < limit) {
                Data data = dataIterator.next();
                if (data.hasStringValue()) {
                    String value = data.getDefaultValueRepresentation();
                    if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                        sb.append(String.format("%s\t%s\n", data.getAddress(), value));
                        count++;
                    }
                }
            }

            if (count == 0) {
                sb.append("No strings found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class SearchFunctionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String query = params.get("query");
            if (query == null || query.isEmpty()) {
                sendError(exchange, 400, "Missing 'query' parameter");
                return;
            }

            int limit = 100;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            FunctionManager fm = program.getFunctionManager();
            FunctionIterator functions = fm.getFunctions(true);
            String queryLower = query.toLowerCase();

            int count = 0;
            while (functions.hasNext() && count < limit) {
                Function f = functions.next();
                if (f.getName().toLowerCase().contains(queryLower)) {
                    sb.append(String.format("%s\t%s\n", f.getEntryPoint(), f.getName()));
                    count++;
                }
            }

            if (count == 0) {
                sb.append("No functions found matching: " + query);
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class ChangesSinceHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            long since = 0;
            if (params.containsKey("since")) {
                try {
                    since = Long.parseLong(params.get("since"));
                } catch (NumberFormatException ignored) {}
            }

            int limit = 100;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            int count = 0;

            for (ChangeRecord record : changeHistory) {
                if (record.timestamp > since && count < limit) {
                    sb.append(String.format("[%d] %s at %s\n",
                        record.timestamp,
                        record.changeType,
                        record.address.isEmpty() ? "unknown" : record.address));
                    if (!record.details.isEmpty()) {
                        sb.append("  ").append(record.details).append("\n");
                    }
                    count++;
                }
            }

            if (count == 0) {
                sb.append("No changes since ").append(since);
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    // POST handlers

    private class SetFunctionPrototypeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("function_address");
            String prototype = params.get("prototype");

            if (addressStr == null || prototype == null) {
                sendError(exchange, 400, "Missing required parameters: function_address, prototype");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                sendError(exchange, 404, "No function at address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set function prototype");
                try {
                    // Parse and apply the prototype
                    ghidra.program.model.listing.FunctionSignature sig = parseSignature(prototype, function);
                    ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                        new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                            function.getEntryPoint(),
                            sig,
                            SourceType.USER_DEFINED
                        );
                    cmd.applyTo(program);
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Prototype updated for " + function.getName());
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (ghidra.app.util.cparser.C.ParseException e) {
                String userMsg = CParserUtils.handleParseProblem(e, prototype);
                sendError(exchange, 400, "Invalid prototype: " + (userMsg != null ? userMsg : e.getMessage()));
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set prototype: " + e.getMessage());
            }
        }

        private ghidra.program.model.listing.FunctionSignature parseSignature(String prototype, Function function)
                throws Exception {
            // Get DataTypeManagerService from tool for access to open archives
            DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);

            // Use CParserUtils with handleExceptions=false to throw instead of showing dialog
            ghidra.program.model.data.FunctionDefinitionDataType sig =
                CParserUtils.parseSignature(dtms, program, prototype, false);

            if (sig == null) {
                throw new Exception("Failed to parse signature: " + prototype);
            }

            return sig;
        }
    }

    private class RenameFunctionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("function_address");
            String newName = params.get("new_name");

            if (addressStr == null || newName == null) {
                sendError(exchange, 400, "Missing required parameters: function_address, new_name");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                sendError(exchange, 404, "No function at address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Rename function");
                try {
                    function.setName(newName, SourceType.USER_DEFINED);
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Function renamed to: " + newName);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to rename function: " + e.getMessage());
            }
        }
    }

    private class SetLocalVariableTypeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("function_address");
            String varName = params.get("variable_name");
            String newType = params.get("new_type");

            if (addressStr == null || varName == null || newType == null) {
                sendError(exchange, 400, "Missing required parameters: function_address, variable_name, new_type");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                sendError(exchange, 404, "No function at address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set variable type");
                try {
                    // Find the variable
                    Variable foundVar = null;
                    for (Variable var : function.getAllVariables()) {
                        if (var.getName().equals(varName)) {
                            foundVar = var;
                            break;
                        }
                    }

                    if (foundVar == null) {
                        program.endTransaction(txId, false);
                        sendError(exchange, 404, "Variable not found: " + varName);
                        return;
                    }

                    // Parse and apply the new type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = dtm.getDataType("/" + newType);
                    if (dataType == null) {
                        // Try built-in types
                        dataType = program.getDataTypeManager().getDataType("/" + newType);
                    }

                    if (dataType != null) {
                        foundVar.setDataType(dataType, SourceType.USER_DEFINED);
                    }

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Variable type updated: " + varName + " -> " + newType);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set variable type: " + e.getMessage());
            }
        }
    }

    private class SetDecompilerCommentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String comment = params.get("comment");

            if (addressStr == null || comment == null) {
                sendError(exchange, 400, "Missing required parameters: address, comment");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set decompiler comment");
                try {
                    // Set PRE comment which is shown in decompiler view
                    CodeUnit cu = program.getListing().getCodeUnitAt(address);
                    if (cu != null) {
                        cu.setComment(CodeUnit.PRE_COMMENT, comment);
                    }
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Decompiler comment set at: " + addressStr);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set comment: " + e.getMessage());
            }
        }
    }

    private class SetDisassemblyCommentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String comment = params.get("comment");

            if (addressStr == null || comment == null) {
                sendError(exchange, 400, "Missing required parameters: address, comment");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set disassembly comment");
                try {
                    // Set EOL comment which is shown in disassembly view
                    CodeUnit cu = program.getListing().getCodeUnitAt(address);
                    if (cu != null) {
                        cu.setComment(CodeUnit.EOL_COMMENT, comment);
                    }
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Disassembly comment set at: " + addressStr);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set comment: " + e.getMessage());
            }
        }
    }

    // Type handlers

    private class ListTypesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            String category = params.get("category");
            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            DataTypeManager dtm = program.getDataTypeManager();
            int count = 0;

            Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext() && count < limit) {
                DataType dt = iter.next();
                if (category != null && !dt.getCategoryPath().getPath().contains(category)) {
                    continue;
                }
                sb.append(formatDataType(dt)).append("\n");
                count++;
            }

            if (count == 0) {
                sb.append("No types found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class GetTypeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String name = params.get("name");
            if (name == null) {
                sendError(exchange, 400, "Missing 'name' parameter");
                return;
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataType(dtm, name);

            if (dt == null) {
                sendError(exchange, 404, "Type not found: " + name);
                return;
            }

            sendResponse(exchange, 200, formatDataTypeDetailed(dt));
        }
    }

    private class SearchTypesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String query = params.get("query");
            if (query == null || query.isEmpty()) {
                sendError(exchange, 400, "Missing 'query' parameter");
                return;
            }

            int limit = 100;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            DataTypeManager dtm = program.getDataTypeManager();
            String queryLower = query.toLowerCase();
            int count = 0;

            Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext() && count < limit) {
                DataType dt = iter.next();
                if (dt.getName().toLowerCase().contains(queryLower)) {
                    sb.append(formatDataType(dt)).append("\n");
                    count++;
                }
            }

            if (count == 0) {
                sb.append("No types found matching: " + query);
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class CreateTypeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String name = params.get("name");
            String kind = params.get("kind"); // struct, union, typedef, enum
            String definition = params.get("definition");

            if (name == null || kind == null) {
                sendError(exchange, 400, "Missing required parameters: name, kind");
                return;
            }

            try {
                int txId = program.startTransaction("Create type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType newType = null;

                    switch (kind.toLowerCase()) {
                        case "struct":
                            StructureDataType struct = new StructureDataType(name, 0);
                            if (definition != null && !definition.isEmpty()) {
                                parseStructDefinition(struct, definition, dtm);
                            }
                            newType = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                            break;
                        case "union":
                            UnionDataType union = new UnionDataType(name);
                            if (definition != null && !definition.isEmpty()) {
                                parseUnionDefinition(union, definition, dtm);
                            }
                            newType = dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
                            break;
                        case "typedef":
                        case "alias":
                            if (definition == null || definition.isEmpty()) {
                                program.endTransaction(txId, false);
                                sendError(exchange, 400, "Typedef requires 'definition' parameter with base type");
                                return;
                            }
                            DataType baseType = findDataType(dtm, definition);
                            if (baseType == null) {
                                program.endTransaction(txId, false);
                                sendError(exchange, 400, "Base type not found: " + definition);
                                return;
                            }
                            TypedefDataType typedef = new TypedefDataType(name, baseType);
                            newType = dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);
                            break;
                        case "enum":
                            EnumDataType enumType = new EnumDataType(name, 4);
                            if (definition != null && !definition.isEmpty()) {
                                parseEnumDefinition(enumType, definition);
                            }
                            newType = dtm.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);
                            break;
                        default:
                            program.endTransaction(txId, false);
                            sendError(exchange, 400, "Unknown type kind: " + kind);
                            return;
                    }

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Created type: " + newType.getPathName());
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to create type: " + e.getMessage());
            }
        }
    }

    private class UpdateTypeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String name = params.get("name");
            String definition = params.get("definition");
            String newName = params.get("new_name");

            if (name == null) {
                sendError(exchange, 400, "Missing required parameter: name");
                return;
            }

            try {
                int txId = program.startTransaction("Update type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataType(dtm, name);

                    if (dt == null) {
                        program.endTransaction(txId, false);
                        sendError(exchange, 404, "Type not found: " + name);
                        return;
                    }

                    // Handle rename
                    if (newName != null && !newName.isEmpty()) {
                        try {
                            dt.setName(newName);
                        } catch (Exception e) {
                            program.endTransaction(txId, false);
                            sendError(exchange, 400, "Failed to rename type: " + e.getMessage());
                            return;
                        }
                    }

                    // Handle definition update for composite types
                    if (definition != null && !definition.isEmpty()) {
                        if (dt instanceof Structure) {
                            Structure struct = (Structure) dt;
                            struct.deleteAll();
                            parseStructDefinition(struct, definition, dtm);
                        } else if (dt instanceof Union) {
                            Union union = (Union) dt;
                            // Clear all components
                            while (union.getNumComponents() > 0) {
                                union.delete(0);
                            }
                            parseUnionDefinition(union, definition, dtm);
                        } else if (dt instanceof ghidra.program.model.data.Enum) {
                            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                            // Clear and repopulate
                            for (String valueName : enumType.getNames()) {
                                enumType.remove(valueName);
                            }
                            parseEnumDefinition(enumType, definition);
                        }
                    }

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Updated type: " + dt.getPathName());
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to update type: " + e.getMessage());
            }
        }
    }

    // Equate handlers

    private class ListEquatesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            EquateTable equateTable = program.getEquateTable();
            Iterator<Equate> iter = equateTable.getEquates();
            int count = 0;

            while (iter.hasNext() && count < limit) {
                Equate eq = iter.next();
                sb.append(formatEquate(eq)).append("\n");
                count++;
            }

            if (count == 0) {
                sb.append("No equates found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class GetEquateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            String name = params.get("name");
            String valueStr = params.get("value");

            EquateTable equateTable = program.getEquateTable();
            Equate eq = null;

            if (name != null) {
                eq = equateTable.getEquate(name);
            } else if (valueStr != null) {
                try {
                    long value = parseNumber(valueStr);
                    List<Equate> equates = equateTable.getEquates(value);
                    if (!equates.isEmpty()) {
                        eq = equates.get(0);
                    }
                } catch (NumberFormatException e) {
                    sendError(exchange, 400, "Invalid value: " + valueStr);
                    return;
                }
            } else {
                sendError(exchange, 400, "Missing 'name' or 'value' parameter");
                return;
            }

            if (eq == null) {
                sendError(exchange, 404, "Equate not found");
                return;
            }

            sendResponse(exchange, 200, formatEquateDetailed(eq));
        }
    }

    private class SetEquateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String name = params.get("name");
            String valueStr = params.get("value");
            String addressStr = params.get("address");
            String operandStr = params.get("operand");

            if (name == null || valueStr == null) {
                sendError(exchange, 400, "Missing required parameters: name, value");
                return;
            }

            long value;
            try {
                value = parseNumber(valueStr);
            } catch (NumberFormatException e) {
                sendError(exchange, 400, "Invalid value: " + valueStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set equate");
                try {
                    EquateTable equateTable = program.getEquateTable();
                    Equate eq = equateTable.getEquate(name);

                    if (eq == null) {
                        eq = equateTable.createEquate(name, value);
                    }

                    // If address is provided, apply equate at that location
                    if (addressStr != null) {
                        Address addr = parseAddress(addressStr);
                        if (addr == null) {
                            program.endTransaction(txId, false);
                            sendError(exchange, 400, "Invalid address: " + addressStr);
                            return;
                        }
                        int operand = 0;
                        if (operandStr != null) {
                            try {
                                operand = Integer.parseInt(operandStr);
                            } catch (NumberFormatException ignored) {}
                        }
                        eq.addReference(addr, operand);
                    }

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Equate set: " + name + " = " + value);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set equate: " + e.getMessage());
            }
        }
    }

    private class DeleteEquateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String name = params.get("name");
            String addressStr = params.get("address");
            String operandStr = params.get("operand");

            if (name == null) {
                sendError(exchange, 400, "Missing required parameter: name");
                return;
            }

            try {
                int txId = program.startTransaction("Delete equate");
                try {
                    EquateTable equateTable = program.getEquateTable();
                    Equate eq = equateTable.getEquate(name);

                    if (eq == null) {
                        program.endTransaction(txId, false);
                        sendError(exchange, 404, "Equate not found: " + name);
                        return;
                    }

                    if (addressStr != null) {
                        // Remove reference at specific address
                        Address addr = parseAddress(addressStr);
                        if (addr == null) {
                            program.endTransaction(txId, false);
                            sendError(exchange, 400, "Invalid address: " + addressStr);
                            return;
                        }
                        int operand = 0;
                        if (operandStr != null) {
                            try {
                                operand = Integer.parseInt(operandStr);
                            } catch (NumberFormatException ignored) {}
                        }
                        eq.removeReference(addr, operand);
                        program.endTransaction(txId, true);
                        sendResponse(exchange, 200, "Equate reference removed at: " + addressStr);
                    } else {
                        // Delete the entire equate
                        equateTable.removeEquate(name);
                        program.endTransaction(txId, true);
                        sendResponse(exchange, 200, "Equate deleted: " + name);
                    }
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to delete equate: " + e.getMessage());
            }
        }
    }

    // Label handlers

    private class ListLabelsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            String addressStr = params.get("address");
            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            SymbolTable symbolTable = program.getSymbolTable();
            int count = 0;

            if (addressStr != null) {
                // List labels at specific address
                Address address = parseAddress(addressStr);
                if (address == null) {
                    sendError(exchange, 400, "Invalid address: " + addressStr);
                    return;
                }
                Symbol[] symbols = symbolTable.getSymbols(address);
                for (Symbol sym : symbols) {
                    if (sym.getSymbolType() == SymbolType.LABEL) {
                        sb.append(formatSymbol(sym)).append("\n");
                        count++;
                    }
                }
            } else {
                // List all labels
                SymbolIterator symbols = symbolTable.getSymbolIterator();
                while (symbols.hasNext() && count < limit) {
                    Symbol sym = symbols.next();
                    if (sym.getSymbolType() == SymbolType.LABEL) {
                        sb.append(formatSymbol(sym)).append("\n");
                        count++;
                    }
                }
            }

            if (count == 0) {
                sb.append("No labels found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class SetLabelHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String labelName = params.get("name");
            String scope = params.get("scope"); // "global" or "local" (function-scoped)

            if (addressStr == null || labelName == null) {
                sendError(exchange, 400, "Missing required parameters: address, name");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set label");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();
                    Namespace namespace = null;

                    // Determine namespace based on scope
                    if ("local".equalsIgnoreCase(scope)) {
                        // Find the containing function for local scope
                        Function func = program.getFunctionManager().getFunctionContaining(address);
                        if (func != null) {
                            namespace = func;
                        }
                    }
                    // If namespace is null, it will be global

                    Symbol symbol = symbolTable.createLabel(address, labelName, namespace, SourceType.USER_DEFINED);
                    program.endTransaction(txId, true);

                    String scopeDesc = namespace != null ? "local to " + namespace.getName() : "global";
                    sendResponse(exchange, 200, String.format("Label created: %s at %s (%s)", labelName, addressStr, scopeDesc));
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to create label: " + e.getMessage());
            }
        }
    }

    private class DeleteLabelHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String labelName = params.get("name");

            if (addressStr == null || labelName == null) {
                sendError(exchange, 400, "Missing required parameters: address, name");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Delete label");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();
                    Symbol[] symbols = symbolTable.getSymbols(address);
                    Symbol toDelete = null;

                    for (Symbol sym : symbols) {
                        if (sym.getName().equals(labelName) && sym.getSymbolType() == SymbolType.LABEL) {
                            toDelete = sym;
                            break;
                        }
                    }

                    if (toDelete == null) {
                        program.endTransaction(txId, false);
                        sendError(exchange, 404, "Label not found: " + labelName + " at " + addressStr);
                        return;
                    }

                    boolean deleted = toDelete.delete();
                    if (!deleted) {
                        program.endTransaction(txId, false);
                        sendError(exchange, 500, "Failed to delete label (may be primary symbol)");
                        return;
                    }

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Label deleted: " + labelName + " at " + addressStr);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to delete label: " + e.getMessage());
            }
        }
    }

    private String formatSymbol(Symbol sym) {
        String namespace = sym.getParentNamespace().getName();
        if ("Global".equals(namespace)) {
            namespace = "global";
        }
        return String.format("%s\t%s\t%s", sym.getAddress(), sym.getName(), namespace);
    }

    // Namespace handler

    private class ListNamespacesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbols = symbolTable.getSymbolIterator();
            int count = 0;

            while (symbols.hasNext() && count < limit) {
                Symbol sym = symbols.next();
                if (sym.getSymbolType() == SymbolType.NAMESPACE) {
                    String parent = sym.getParentNamespace().getName();
                    if ("Global".equals(parent)) {
                        parent = "global";
                    }
                    sb.append(String.format("%s\t%s\n", sym.getName(), parent));
                    count++;
                }
            }

            if (count == 0) {
                sb.append("No namespaces found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    // Class handler

    private class ListClassesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            StringBuilder sb = new StringBuilder();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbols = symbolTable.getSymbolIterator();
            int count = 0;

            while (symbols.hasNext() && count < limit) {
                Symbol sym = symbols.next();
                if (sym.getSymbolType() == SymbolType.CLASS) {
                    String parent = sym.getParentNamespace().getName();
                    if ("Global".equals(parent)) {
                        parent = "global";
                    }
                    sb.append(String.format("%s\t%s\n", sym.getName(), parent));
                    count++;
                }
            }

            if (count == 0) {
                sb.append("No classes found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    // Import handler

    private class ListImportsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            String filter = params.get("filter");

            StringBuilder sb = new StringBuilder();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbols = symbolTable.getExternalSymbols();
            int count = 0;

            while (symbols.hasNext() && count < limit) {
                Symbol sym = symbols.next();
                String name = sym.getName();
                if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
                String library = sym.getParentNamespace().getName();
                sb.append(String.format("%s\t%s\t%s\n", sym.getAddress(), name, library));
                count++;
            }

            if (count == 0) {
                sb.append("No imports found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    // Export handler

    private class ListExportsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            int limit = 1000;
            if (params.containsKey("limit")) {
                try {
                    limit = Integer.parseInt(params.get("limit"));
                } catch (NumberFormatException ignored) {}
            }

            String filter = params.get("filter");

            StringBuilder sb = new StringBuilder();
            SymbolTable symbolTable = program.getSymbolTable();
            AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
            int count = 0;

            while (entryPoints.hasNext() && count < limit) {
                Address addr = entryPoints.next();
                Symbol sym = symbolTable.getPrimarySymbol(addr);
                String name = (sym != null) ? sym.getName() : addr.toString();
                if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
                sb.append(String.format("%s\t%s\n", addr, name));
                count++;
            }

            if (count == 0) {
                sb.append("No exports found");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    // Memory read handler

    private class ReadMemoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            String addressStr = params.get("address");
            String lengthStr = params.get("length");

            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            int length = 256; // Default length
            if (lengthStr != null) {
                try {
                    length = Integer.parseInt(lengthStr);
                    if (length <= 0 || length > 65536) {
                        sendError(exchange, 400, "Length must be between 1 and 65536");
                        return;
                    }
                } catch (NumberFormatException e) {
                    sendError(exchange, 400, "Invalid length: " + lengthStr);
                    return;
                }
            }

            try {
                ghidra.program.model.mem.Memory memory = program.getMemory();
                byte[] bytes = new byte[length];
                int bytesRead = memory.getBytes(address, bytes);

                if (bytesRead <= 0) {
                    sendError(exchange, 404, "No memory at address: " + addressStr);
                    return;
                }

                String result = formatHexDump(address, bytes, bytesRead);
                sendResponse(exchange, 200, result);
            } catch (ghidra.program.model.mem.MemoryAccessException e) {
                sendError(exchange, 404, "Cannot read memory at: " + addressStr + " - " + e.getMessage());
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to read memory: " + e.getMessage());
            }
        }
    }

    private String formatHexDump(Address startAddr, byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int offset = 0; offset < length; offset += bytesPerLine) {
            // Calculate current address
            Address lineAddr = startAddr.add(offset);

            // Address column
            sb.append(String.format("%s  ", lineAddr));

            // Hex bytes column
            StringBuilder hexPart = new StringBuilder();
            StringBuilder asciiPart = new StringBuilder();

            for (int i = 0; i < bytesPerLine; i++) {
                if (offset + i < length) {
                    byte b = bytes[offset + i];
                    hexPart.append(String.format("%02x ", b & 0xFF));

                    // ASCII representation
                    if (b >= 0x20 && b < 0x7F) {
                        asciiPart.append((char) b);
                    } else {
                        asciiPart.append('.');
                    }
                } else {
                    hexPart.append("   ");
                    asciiPart.append(' ');
                }

                // Add extra space after 8 bytes for readability
                if (i == 7) {
                    hexPart.append(" ");
                }
            }

            sb.append(hexPart);
            sb.append(" |").append(asciiPart).append("|\n");
        }

        return sb.toString();
    }

    // Data type assignment handlers

    private class GetDataHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }
            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());

            String addressStr = params.get("address");
            if (addressStr == null) {
                sendError(exchange, 400, "Missing 'address' parameter");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            Listing listing = program.getListing();
            Data data = listing.getDataAt(address);

            if (data == null) {
                // Check if it's within a data item
                data = listing.getDataContaining(address);
                if (data == null) {
                    sendResponse(exchange, 200, "No data defined at: " + addressStr);
                    return;
                }
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Address: ").append(data.getAddress()).append("\n");
            sb.append("Type: ").append(data.getDataType().getPathName()).append("\n");
            sb.append("Size: ").append(data.getLength()).append(" bytes\n");
            sb.append("Value: ").append(data.getDefaultValueRepresentation()).append("\n");

            if (data.hasStringValue()) {
                sb.append("String: ").append(data.getDefaultValueRepresentation()).append("\n");
            }

            // Show labels at this address
            Symbol[] symbols = program.getSymbolTable().getSymbols(data.getAddress());
            if (symbols.length > 0) {
                sb.append("Labels: ");
                for (int i = 0; i < symbols.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(symbols[i].getName());
                }
                sb.append("\n");
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class SetDataTypeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String typeName = params.get("type");

            if (addressStr == null || typeName == null) {
                sendError(exchange, 400, "Missing required parameters: address, type");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = findDataTypeForData(dtm, typeName);

            if (dataType == null) {
                sendError(exchange, 404, "Data type not found: " + typeName);
                return;
            }

            try {
                int txId = program.startTransaction("Set data type");
                try {
                    Listing listing = program.getListing();

                    // Clear any existing data at this location
                    listing.clearCodeUnits(address, address.add(dataType.getLength() - 1), false);

                    // Create the data
                    Data newData = listing.createData(address, dataType);

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, String.format("Data type set: %s at %s (%d bytes)",
                        dataType.getName(), addressStr, newData.getLength()));
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set data type: " + e.getMessage());
            }
        }
    }

    private class ClearDataHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String lengthStr = params.get("length");

            if (addressStr == null) {
                sendError(exchange, 400, "Missing required parameter: address");
                return;
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            int length = 1;
            if (lengthStr != null) {
                try {
                    length = Integer.parseInt(lengthStr);
                } catch (NumberFormatException e) {
                    sendError(exchange, 400, "Invalid length: " + lengthStr);
                    return;
                }
            }

            try {
                int txId = program.startTransaction("Clear data");
                try {
                    Listing listing = program.getListing();
                    Address endAddr = address.add(length - 1);
                    listing.clearCodeUnits(address, endAddr, false);

                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, String.format("Cleared data from %s to %s",
                        addressStr, endAddr.toString()));
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to clear data: " + e.getMessage());
            }
        }
    }

    private class ProgramInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Name: ").append(program.getName()).append("\n");
            sb.append("Executable Format: ").append(program.getExecutableFormat()).append("\n");
            sb.append("Language ID: ").append(program.getLanguageID()).append("\n");
            sb.append("Compiler Spec: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
            sb.append("Image Base: ").append(program.getImageBase()).append("\n");
            sb.append("Executable Path: ").append(program.getExecutablePath()).append("\n");
            sb.append("MD5: ").append(program.getExecutableMD5()).append("\n");
            sb.append("Min Address: ").append(program.getMinAddress()).append("\n");
            sb.append("Max Address: ").append(program.getMaxAddress()).append("\n");
            sb.append("Function Count: ").append(program.getFunctionManager().getFunctionCount()).append("\n");

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class ListMemoryBlocksHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            int limit = 1000;
            String limitStr = params.get("limit");
            if (limitStr != null) {
                try {
                    limit = Integer.parseInt(limitStr);
                } catch (NumberFormatException e) {
                    sendError(exchange, 400, "Invalid limit: " + limitStr);
                    return;
                }
            }

            MemoryBlock[] blocks = program.getMemory().getBlocks();
            StringBuilder sb = new StringBuilder();
            int count = 0;
            for (MemoryBlock block : blocks) {
                if (count >= limit) break;

                String perms = ""
                    + (block.isRead() ? "r" : "-")
                    + (block.isWrite() ? "w" : "-")
                    + (block.isExecute() ? "x" : "-");

                sb.append(String.format("%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
                    block.getName(),
                    block.getStart(),
                    block.getEnd(),
                    block.getSize(),
                    perms,
                    block.getType().name(),
                    block.isInitialized()));

                count++;
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class ListBookmarksHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseQueryString(exchange.getRequestURI().getQuery());
            int limit = 1000;
            String limitStr = params.get("limit");
            if (limitStr != null) {
                try {
                    limit = Integer.parseInt(limitStr);
                } catch (NumberFormatException e) {
                    sendError(exchange, 400, "Invalid limit: " + limitStr);
                    return;
                }
            }
            String filterType = params.get("type");

            BookmarkManager bmMgr = program.getBookmarkManager();
            Iterator<Bookmark> iter;
            if (filterType != null && !filterType.isEmpty()) {
                iter = bmMgr.getBookmarksIterator(filterType);
            } else {
                iter = bmMgr.getBookmarksIterator();
            }

            StringBuilder sb = new StringBuilder();
            int count = 0;
            while (iter.hasNext() && count < limit) {
                Bookmark bm = iter.next();
                sb.append(String.format("%s\t%s\t%s\t%s\n",
                    bm.getAddress(),
                    bm.getTypeString(),
                    bm.getCategory(),
                    bm.getComment()));
                count++;
            }

            sendResponse(exchange, 200, sb.toString());
        }
    }

    private class SetBookmarkHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String type = params.get("type");
            String category = params.get("category");
            String comment = params.get("comment");

            if (addressStr == null) {
                sendError(exchange, 400, "Missing required parameter: address");
                return;
            }
            if (type == null || type.isEmpty()) {
                type = "Note";
            }
            if (category == null) {
                category = "";
            }
            if (comment == null) {
                comment = "";
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Set bookmark");
                try {
                    program.getBookmarkManager().setBookmark(address, type, category, comment);
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, String.format("Bookmark set at %s (type=%s, category=%s)",
                        addressStr, type, category));
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set bookmark: " + e.getMessage());
            }
        }
    }

    private class DeleteBookmarkHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            if (program == null) {
                sendError(exchange, 503, "No program loaded");
                return;
            }

            Map<String, String> params = parseFormData(exchange);
            String addressStr = params.get("address");
            String type = params.get("type");
            String category = params.get("category");

            if (addressStr == null) {
                sendError(exchange, 400, "Missing required parameter: address");
                return;
            }
            if (type == null || type.isEmpty()) {
                type = "Note";
            }
            if (category == null) {
                category = "";
            }

            Address address = parseAddress(addressStr);
            if (address == null) {
                sendError(exchange, 400, "Invalid address: " + addressStr);
                return;
            }

            try {
                int txId = program.startTransaction("Delete bookmark");
                try {
                    BookmarkManager bmMgr = program.getBookmarkManager();
                    Bookmark bm = bmMgr.getBookmark(address, type, category);
                    if (bm == null) {
                        program.endTransaction(txId, false);
                        sendError(exchange, 404, String.format("No bookmark found at %s (type=%s, category=%s)",
                            addressStr, type, category));
                        return;
                    }
                    bmMgr.removeBookmark(bm);
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, String.format("Bookmark deleted at %s (type=%s, category=%s)",
                        addressStr, type, category));
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to delete bookmark: " + e.getMessage());
            }
        }
    }

    // Helper method to find data types including common built-ins
    private DataType findDataTypeForData(DataTypeManager dtm, String name) {
        // First try the program's data type manager
        DataType dt = findDataType(dtm, name);
        if (dt != null) return dt;

        // Try common built-in types by name
        String lowerName = name.toLowerCase();
        switch (lowerName) {
            case "byte":
            case "db":
                return new ByteDataType();
            case "word":
            case "ushort":
            case "uint16":
            case "dw":
                return new WordDataType();
            case "dword":
            case "uint":
            case "uint32":
            case "dd":
                return new DWordDataType();
            case "qword":
            case "ulong":
            case "uint64":
            case "dq":
                return new QWordDataType();
            case "short":
            case "int16":
                return new ShortDataType();
            case "int":
            case "int32":
                return new IntegerDataType();
            case "long":
            case "int64":
                return new LongDataType();
            case "float":
                return new FloatDataType();
            case "double":
                return new DoubleDataType();
            case "char":
                return new CharDataType();
            case "string":
            case "cstring":
                return new StringDataType();
            case "pointer":
            case "ptr":
                return new PointerDataType();
            case "void":
                return new VoidDataType();
            case "bool":
            case "boolean":
                return new BooleanDataType();
            case "undefined":
            case "undefined1":
                return new Undefined1DataType();
            case "undefined2":
                return new Undefined2DataType();
            case "undefined4":
                return new Undefined4DataType();
            case "undefined8":
                return new Undefined8DataType();
        }

        // Check for pointer syntax like "type *" or "type*"
        if (name.endsWith("*")) {
            String baseTypeName = name.substring(0, name.length() - 1).trim();
            DataType baseType = findDataTypeForData(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
        }

        return null;
    }

    // Helper methods for types and equates

    private DataType findDataType(DataTypeManager dtm, String name) {
        // Try direct lookup first
        DataType dt = dtm.getDataType("/" + name);
        if (dt != null) return dt;

        // Try with full path if it looks like one
        if (name.startsWith("/")) {
            dt = dtm.getDataType(name);
            if (dt != null) return dt;
        }

        // Search through all types
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(name)) {
                return candidate;
            }
        }

        return null;
    }

    private String formatDataType(DataType dt) {
        String kind = getDataTypeKind(dt);
        return String.format("%s\t%s\t%s\t%d", dt.getPathName(), dt.getName(), kind, dt.getLength());
    }

    private String formatDataTypeDetailed(DataType dt) {
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(dt.getName()).append("\n");
        sb.append("Path: ").append(dt.getPathName()).append("\n");
        sb.append("Kind: ").append(getDataTypeKind(dt)).append("\n");
        sb.append("Size: ").append(dt.getLength()).append(" bytes\n");
        sb.append("Description: ").append(dt.getDescription() != null ? dt.getDescription() : "").append("\n");

        if (dt instanceof TypeDef) {
            TypeDef td = (TypeDef) dt;
            sb.append("Base Type: ").append(td.getBaseDataType().getPathName()).append("\n");
        } else if (dt instanceof Structure) {
            Structure struct = (Structure) dt;
            sb.append("\nFields:\n");
            for (DataTypeComponent comp : struct.getComponents()) {
                sb.append(String.format("  %d: %s %s (%d bytes)\n",
                    comp.getOffset(),
                    comp.getDataType().getName(),
                    comp.getFieldName() != null ? comp.getFieldName() : "",
                    comp.getLength()));
            }
        } else if (dt instanceof Union) {
            Union union = (Union) dt;
            sb.append("\nFields:\n");
            for (DataTypeComponent comp : union.getComponents()) {
                sb.append(String.format("  %s %s (%d bytes)\n",
                    comp.getDataType().getName(),
                    comp.getFieldName() != null ? comp.getFieldName() : "",
                    comp.getLength()));
            }
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
            sb.append("\nValues:\n");
            for (String valueName : enumType.getNames()) {
                sb.append(String.format("  %s = 0x%x\n", valueName, enumType.getValue(valueName)));
            }
        }

        return sb.toString();
    }

    private String getDataTypeKind(DataType dt) {
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof Structure) return "struct";
        if (dt instanceof Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof Pointer) return "pointer";
        if (dt instanceof Array) return "array";
        if (dt instanceof FunctionDefinition) return "function";
        return "primitive";
    }

    // Helper class to hold parsed array information
    private static class ArrayTypeInfo {
        final String baseTypeName;
        final List<Integer> dimensions;

        ArrayTypeInfo(String baseTypeName, List<Integer> dimensions) {
            this.baseTypeName = baseTypeName;
            this.dimensions = dimensions;
        }
    }

    // Parse array syntax from type name, e.g., "byte[16]" or "int[4][4]"
    // Returns null if not an array type
    private ArrayTypeInfo parseArraySyntax(String typeName) {
        if (!typeName.contains("[") || !typeName.endsWith("]")) {
            return null;
        }

        // Find where array dimensions start
        int firstBracket = typeName.indexOf('[');
        String baseType = typeName.substring(0, firstBracket).trim();
        String dimensionsPart = typeName.substring(firstBracket);

        // Parse all dimensions like [4][16][32]
        List<Integer> dimensions = new ArrayList<>();
        int i = 0;
        while (i < dimensionsPart.length()) {
            if (dimensionsPart.charAt(i) != '[') {
                return null; // Invalid format
            }
            int closeIdx = dimensionsPart.indexOf(']', i);
            if (closeIdx < 0) {
                return null; // Missing closing bracket
            }
            String sizeStr = dimensionsPart.substring(i + 1, closeIdx).trim();
            try {
                dimensions.add(Integer.parseInt(sizeStr));
            } catch (NumberFormatException e) {
                return null; // Invalid dimension
            }
            i = closeIdx + 1;
        }

        if (dimensions.isEmpty()) {
            return null;
        }

        return new ArrayTypeInfo(baseType, dimensions);
    }

    // Create a DataType, handling array syntax if present
    private DataType createFieldType(String typeName, DataTypeManager dtm) {
        ArrayTypeInfo arrayInfo = parseArraySyntax(typeName);
        if (arrayInfo == null) {
            // Not an array, just find the type directly
            return findDataType(dtm, typeName);
        }

        // Find the base type
        DataType baseType = findDataType(dtm, arrayInfo.baseTypeName);
        if (baseType == null) {
            return null;
        }

        // Build array type from innermost to outermost
        // For int[4][16], we want: ArrayDataType(ArrayDataType(int, 16), 4)
        // So we process dimensions in reverse order
        DataType currentType = baseType;
        for (int i = arrayInfo.dimensions.size() - 1; i >= 0; i--) {
            int size = arrayInfo.dimensions.get(i);
            currentType = new ArrayDataType(currentType, size, currentType.getLength());
        }

        return currentType;
    }

    private void parseStructDefinition(Structure struct, String definition, DataTypeManager dtm) {
        // Parse format: "type1 name1; type2 name2; ..."
        // Also supports array syntax: "byte[16] padding; int[4][4] matrix"
        String[] fields = definition.split(";");
        for (String field : fields) {
            field = field.trim();
            if (field.isEmpty()) continue;

            int lastSpace = field.lastIndexOf(' ');
            if (lastSpace < 0) continue;

            String typeName = field.substring(0, lastSpace).trim();
            String fieldName = field.substring(lastSpace + 1).trim();

            DataType fieldType = createFieldType(typeName, dtm);
            if (fieldType != null) {
                struct.add(fieldType, fieldName, null);
            }
        }
    }

    private void parseUnionDefinition(Union union, String definition, DataTypeManager dtm) {
        // Parse format: "type1 name1; type2 name2; ..."
        // Also supports array syntax: "byte[16] padding; int[4][4] matrix"
        String[] fields = definition.split(";");
        for (String field : fields) {
            field = field.trim();
            if (field.isEmpty()) continue;

            int lastSpace = field.lastIndexOf(' ');
            if (lastSpace < 0) continue;

            String typeName = field.substring(0, lastSpace).trim();
            String fieldName = field.substring(lastSpace + 1).trim();

            DataType fieldType = createFieldType(typeName, dtm);
            if (fieldType != null) {
                union.add(fieldType, fieldName, null);
            }
        }
    }

    private void parseEnumDefinition(ghidra.program.model.data.Enum enumType, String definition) {
        // Parse format: "name1=value1; name2=value2; ..."
        String[] entries = definition.split(";");
        for (String entry : entries) {
            entry = entry.trim();
            if (entry.isEmpty()) continue;

            String[] parts = entry.split("=");
            if (parts.length != 2) continue;

            String name = parts[0].trim();
            try {
                long value = parseNumber(parts[1].trim());
                enumType.add(name, value);
            } catch (NumberFormatException ignored) {}
        }
    }

    private String formatEquate(Equate eq) {
        return String.format("%s\t0x%x\t%d refs", eq.getName(), eq.getValue(), eq.getReferenceCount());
    }

    private String formatEquateDetailed(Equate eq) {
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(eq.getName()).append("\n");
        sb.append("Value: ").append(eq.getValue()).append(" (0x").append(Long.toHexString(eq.getValue())).append(")\n");
        sb.append("Reference Count: ").append(eq.getReferenceCount()).append("\n");

        sb.append("\nReferences:\n");
        for (EquateReference ref : eq.getReferences()) {
            sb.append(String.format("  %s operand %d\n", ref.getAddress(), ref.getOpIndex()));
        }

        return sb.toString();
    }

    private long parseNumber(String str) {
        str = str.trim().toLowerCase();
        if (str.startsWith("0x")) {
            return Long.parseUnsignedLong(str.substring(2), 16);
        } else if (str.startsWith("-")) {
            return Long.parseLong(str);
        } else {
            return Long.parseUnsignedLong(str);
        }
    }

    // Inner class for change tracking
    private static class ChangeRecord {
        final long timestamp;
        final String changeType;
        final String address;
        final String details;

        ChangeRecord(long timestamp, String changeType, String address, String details) {
            this.timestamp = timestamp;
            this.changeType = changeType;
            this.address = address;
            this.details = details;
        }
    }
}
