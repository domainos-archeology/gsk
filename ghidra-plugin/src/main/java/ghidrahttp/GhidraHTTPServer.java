package ghidrahttp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
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
