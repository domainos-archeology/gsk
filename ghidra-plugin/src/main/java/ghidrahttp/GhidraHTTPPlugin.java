package ghidrahttp;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * GhidraHTTP Plugin - Provides an HTTP API for Ghidra operations
 *
 * This plugin starts an HTTP server that exposes Ghidra's analysis capabilities
 * through a REST-like API, enabling external tools to interact with Ghidra.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraHTTP",
    category = PluginCategoryNames.COMMON,
    shortDescription = "HTTP API for Ghidra",
    description = "Provides an HTTP API server for remote access to Ghidra analysis features including decompilation, disassembly, cross-references, and more."
)
//@formatter:on
public class GhidraHTTPPlugin extends ProgramPlugin {

    private GhidraHTTPServer httpServer;
    private int serverPort = 8080;
    private DockingAction startServerAction;
    private DockingAction stopServerAction;

    public GhidraHTTPPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        // Start Server action
        startServerAction = new DockingAction("Start HTTP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                startServer();
            }
        };
        startServerAction.setMenuBarData(new MenuData(
            new String[] { "Tools", "GhidraHTTP", "Start Server" },
            null,
            "GhidraHTTP"
        ));
        startServerAction.setEnabled(true);
        tool.addAction(startServerAction);

        // Stop Server action
        stopServerAction = new DockingAction("Stop HTTP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopServer();
            }
        };
        stopServerAction.setMenuBarData(new MenuData(
            new String[] { "Tools", "GhidraHTTP", "Stop Server" },
            null,
            "GhidraHTTP"
        ));
        stopServerAction.setEnabled(false);
        tool.addAction(stopServerAction);
    }

    @Override
    protected void init() {
        super.init();
        // Auto-start the server when plugin loads
        startServer();
    }

    @Override
    protected void dispose() {
        stopServer();
        super.dispose();
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        if (httpServer != null) {
            httpServer.setProgram(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        if (httpServer != null) {
            httpServer.setProgram(null);
        }
    }

    private void startServer() {
        if (httpServer != null && httpServer.isRunning()) {
            Msg.showInfo(this, null, "GhidraHTTP", "Server is already running on port " + serverPort);
            return;
        }

        try {
            httpServer = new GhidraHTTPServer(serverPort, tool, currentProgram);
            httpServer.start();
            startServerAction.setEnabled(false);
            stopServerAction.setEnabled(true);
            Msg.showInfo(this, null, "GhidraHTTP", "HTTP Server started on port " + serverPort);
        } catch (Exception e) {
            Msg.showError(this, null, "GhidraHTTP Error",
                "Failed to start HTTP server: " + e.getMessage(), e);
        }
    }

    private void stopServer() {
        if (httpServer != null) {
            httpServer.stop();
            httpServer = null;
            startServerAction.setEnabled(true);
            stopServerAction.setEnabled(false);
            Msg.showInfo(this, null, "GhidraHTTP", "HTTP Server stopped");
        }
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int port) {
        this.serverPort = port;
    }

    public boolean isServerRunning() {
        return httpServer != null && httpServer.isRunning();
    }
}
