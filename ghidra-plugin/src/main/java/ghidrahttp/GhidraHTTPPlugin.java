package ghidrahttp;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * GhidraHTTP Plugin - Provides an HTTP API for Ghidra operations.
 *
 * This plugin lives in the Ghidra project window (the front-end tool), not in a CodeBrowser.
 * That means exactly one HTTP server per Ghidra session, and the server can address any
 * program in the open project, whether or not it is open in a CodeBrowser window.
 *
 * If the plugin does not show up automatically, enable it in the project window via
 * File -> Configure -> GhidraHTTP.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraHTTP",
    category = PluginCategoryNames.COMMON,
    shortDescription = "HTTP API for Ghidra",
    description = "Provides an HTTP API server for remote access to Ghidra analysis features including decompilation, disassembly, cross-references, and more. Runs in the project window and can operate on every program in the project."
)
//@formatter:on
public class GhidraHTTPPlugin extends Plugin implements ApplicationLevelOnlyPlugin, ProjectListener {

    private GhidraHTTPServer httpServer;
    private ProgramRegistry registry;
    private int serverPort = 8080;
    private DockingAction startServerAction;
    private DockingAction stopServerAction;

    public GhidraHTTPPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        startServerAction = new DockingAction("Start HTTP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                startServer(true);
            }
        };
        startServerAction.setMenuBarData(new MenuData(
            new String[] { "Tools", "GhidraHTTP", "Start Server" },
            null,
            "GhidraHTTP"
        ));
        startServerAction.setEnabled(true);
        tool.addAction(startServerAction);

        stopServerAction = new DockingAction("Stop HTTP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopServer(true);
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
        FrontEndService frontEnd = tool.getService(FrontEndService.class);
        if (frontEnd != null) {
            frontEnd.addProjectListener(this);
        }
        // Auto-start the server when the plugin loads; log rather than pop a dialog.
        startServer(false);
    }

    @Override
    protected void dispose() {
        FrontEndService frontEnd = tool.getService(FrontEndService.class);
        if (frontEnd != null) {
            frontEnd.removeProjectListener(this);
        }
        stopServer(false);
        super.dispose();
    }

    // ProjectListener: drop any programs we hold when the project goes away.

    @Override
    public void projectOpened(Project project) {
        // Nothing to do; programs are resolved lazily against the active project.
    }

    @Override
    public void projectClosed(Project project) {
        if (registry != null) {
            registry.releaseAll();
        }
        if (httpServer != null) {
            httpServer.clearTracking();
        }
    }

    private void startServer(boolean interactive) {
        if (httpServer != null && httpServer.isRunning()) {
            if (interactive) {
                Msg.showInfo(this, null, "GhidraHTTP", "Server is already running on port " + serverPort);
            }
            return;
        }

        try {
            registry = new ProgramRegistry(tool);
            httpServer = new GhidraHTTPServer(serverPort, tool, registry);
            httpServer.start();
            startServerAction.setEnabled(false);
            stopServerAction.setEnabled(true);
            if (interactive) {
                Msg.showInfo(this, null, "GhidraHTTP", "HTTP Server started on port " + serverPort);
            }
        } catch (Exception e) {
            httpServer = null;
            if (interactive) {
                Msg.showError(this, null, "GhidraHTTP Error",
                    "Failed to start HTTP server: " + e.getMessage(), e);
            } else {
                Msg.error(this, "Failed to start HTTP server on port " + serverPort + ": " + e.getMessage());
            }
        }
    }

    private void stopServer(boolean interactive) {
        if (httpServer != null) {
            httpServer.stop();
            httpServer = null;
            if (registry != null) {
                registry.releaseAll();
                registry = null;
            }
            startServerAction.setEnabled(true);
            stopServerAction.setEnabled(false);
            if (interactive) {
                Msg.showInfo(this, null, "GhidraHTTP", "HTTP Server stopped");
            }
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
