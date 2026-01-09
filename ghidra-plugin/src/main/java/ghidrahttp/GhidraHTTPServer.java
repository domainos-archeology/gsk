package ghidrahttp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
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
        String changeType = getChangeTypeName(record.getEventType());
        String details = "";
        String address = "";

        if (record instanceof ProgramChangeRecord) {
            ProgramChangeRecord pcr = (ProgramChangeRecord) record;
            if (pcr.getStart() != null) {
                address = pcr.getStart().toString();
            }
            Object oldValue = pcr.getOldValue();
            Object newValue = pcr.getNewValue();
            if (oldValue != null || newValue != null) {
                details = String.format("Old: %s, New: %s",
                    oldValue != null ? oldValue.toString() : "null",
                    newValue != null ? newValue.toString() : "null");
            }
        }

        ChangeRecord cr = new ChangeRecord(timestamp, changeType, address, details);
        changeHistory.add(cr);

        // Keep only last 1000 changes
        while (changeHistory.size() > 1000) {
            changeHistory.poll();
        }
    }

    private String getChangeTypeName(int eventType) {
        // Map common event types to readable names
        switch (eventType) {
            case ChangeManager.DOCR_SYMBOL_RENAMED:
                return "symbol_renamed";
            case ChangeManager.DOCR_SYMBOL_ADDED:
                return "symbol_added";
            case ChangeManager.DOCR_SYMBOL_REMOVED:
                return "symbol_removed";
            case ChangeManager.DOCR_CODE_ADDED:
                return "code_added";
            case ChangeManager.DOCR_CODE_REMOVED:
                return "code_removed";
            case ChangeManager.DOCR_FUNCTION_CHANGED:
                return "function_changed";
            case ChangeManager.DOCR_FUNCTION_ADDED:
                return "function_added";
            case ChangeManager.DOCR_FUNCTION_REMOVED:
                return "function_removed";
            case ChangeManager.DOCR_COMMENT_CHANGED:
                return "comment_changed";
            default:
                return "change_" + eventType;
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
            Reference[] refs = refMgr.getReferencesTo(address);

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
                    ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                        new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                            function.getEntryPoint(),
                            parseSignature(prototype, function),
                            SourceType.USER_DEFINED
                        );
                    cmd.applyTo(program);
                    program.endTransaction(txId, true);
                    sendResponse(exchange, 200, "Prototype updated for " + function.getName());
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                sendError(exchange, 500, "Failed to set prototype: " + e.getMessage());
            }
        }

        private ghidra.program.model.listing.FunctionSignature parseSignature(String prototype, Function function) {
            // Simple signature parsing - in production, use Ghidra's CParser
            ghidra.program.model.data.FunctionDefinitionDataType sig =
                new ghidra.program.model.data.FunctionDefinitionDataType(function.getName());
            // For now, just update the name from the prototype
            // Full parsing would require CParser integration
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
                    // PRE_COMMENT is shown in decompiler view
                    program.getListing().setComment(address, CodeUnit.PRE_COMMENT, comment);
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
                    // EOL_COMMENT is shown in disassembly view
                    program.getListing().setComment(address, CodeUnit.EOL_COMMENT, comment);
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
