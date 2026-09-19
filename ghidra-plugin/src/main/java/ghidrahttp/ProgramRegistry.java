package ghidrahttp;

import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves project paths to open {@link Program}s and keeps track of the programs the
 * HTTP server has opened itself.
 *
 * The registry lives in the Ghidra project window (front-end tool), so it can see the whole
 * project regardless of which CodeBrowser windows are open. Programs are opened hidden
 * (no GUI) with this registry as the consumer; programs that a CodeBrowser already has open
 * are shared rather than opened a second time.
 */
public class ProgramRegistry {

    /** Thrown when a program spec cannot be resolved; carries an HTTP status. */
    public static class ResolveException extends Exception {
        private static final long serialVersionUID = 1L;
        public final int status;

        public ResolveException(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    /** One row of the "open programs" listing. */
    public static class OpenProgram {
        public final Program program;
        public final String path;
        public final boolean openedByServer;
        public final List<String> tools = new ArrayList<>();
        public boolean activeInTool;

        OpenProgram(Program program, boolean openedByServer) {
            this.program = program;
            this.path = pathOf(program);
            this.openedByServer = openedByServer;
        }
    }

    private final PluginTool tool;
    /** Programs this registry opened, keyed by project path. */
    private final Map<String, Program> opened = new LinkedHashMap<>();

    public ProgramRegistry(PluginTool tool) {
        this.tool = tool;
    }

    // ---- project access ----

    public Project getProject() {
        Project project = tool != null ? tool.getProject() : null;
        if (project == null) {
            project = AppInfo.getActiveProject();
        }
        return project;
    }

    private ProjectData requireProjectData() throws ResolveException {
        Project project = getProject();
        if (project == null) {
            throw new ResolveException(503, "No project is open in Ghidra");
        }
        return project.getProjectData();
    }

    /**
     * Find a project file from a spec: an absolute project path ("/dir/file"), a path without
     * the leading slash, or a bare file name that is unique within the project.
     */
    public DomainFile findFile(String spec) throws ResolveException {
        if (spec == null || spec.isEmpty()) {
            throw new ResolveException(400, "Empty program path");
        }
        ProjectData pd = requireProjectData();

        String path = spec.startsWith("/") ? spec : "/" + spec;
        DomainFile df = pd.getFile(path);
        if (df != null) {
            return df;
        }

        // Fall back to a unique name match anywhere in the project.
        List<DomainFile> matches = new ArrayList<>();
        collectFiles(pd.getRootFolder(), true, f -> f.getName().equals(spec), matches);
        if (matches.size() == 1) {
            return matches.get(0);
        }
        if (matches.size() > 1) {
            StringBuilder sb = new StringBuilder("Ambiguous program name '" + spec + "', matches:");
            for (DomainFile m : matches) {
                sb.append(' ').append(m.getPathname());
            }
            throw new ResolveException(400, sb.toString());
        }
        throw new ResolveException(404, "Program not found in project: " + spec);
    }

    private interface FileFilter {
        boolean accept(DomainFile f);
    }

    private void collectFiles(DomainFolder folder, boolean recursive, FileFilter filter,
            List<DomainFile> out) {
        for (DomainFile f : folder.getFiles()) {
            if (filter == null || filter.accept(f)) {
                out.add(f);
            }
        }
        if (recursive) {
            for (DomainFolder sub : folder.getFolders()) {
                collectFiles(sub, true, filter, out);
            }
        }
    }

    /** List files in a project folder. */
    public List<DomainFile> listProjectFiles(String folderPath, boolean recursive)
            throws ResolveException {
        ProjectData pd = requireProjectData();
        DomainFolder folder;
        if (folderPath == null || folderPath.isEmpty() || folderPath.equals("/")) {
            folder = pd.getRootFolder();
        } else {
            folder = pd.getFolder(folderPath.startsWith("/") ? folderPath : "/" + folderPath);
            if (folder == null) {
                throw new ResolveException(404, "Folder not found in project: " + folderPath);
            }
        }
        List<DomainFile> out = new ArrayList<>();
        collectFiles(folder, recursive, null, out);
        return out;
    }

    public static boolean isProgramFile(DomainFile df) {
        Class<?> cls = df.getDomainObjectClass();
        return cls != null && Program.class.isAssignableFrom(cls);
    }

    public static String pathOf(Program p) {
        DomainFile df = p.getDomainFile();
        return df != null ? df.getPathname() : p.getName();
    }

    // ---- resolution ----

    /**
     * Resolve a program spec. A null or empty spec means "the default program": the active
     * program of a running CodeBrowser, or the only program this registry has opened.
     */
    public synchronized Program resolve(String spec) throws ResolveException {
        if (spec == null || spec.isEmpty()) {
            Program p = defaultProgram();
            if (p == null) {
                throw new ResolveException(503,
                    "No program specified and none active. Pass program=<project path> " +
                    "(or use --program / .gsk.yaml), or open one in a CodeBrowser.");
            }
            return p;
        }

        DomainFile df = findFile(spec);
        if (!isProgramFile(df)) {
            throw new ResolveException(400,
                "Not a program: " + df.getPathname() + " (" + df.getContentType() + ")");
        }
        String path = df.getPathname();

        Program existing = opened.get(path);
        if (existing != null && !existing.isClosed()) {
            return existing;
        }
        opened.remove(path);

        // Share an instance a CodeBrowser already has open, otherwise open hidden.
        DomainObject obj = df.getOpenedDomainObject(this);
        if (obj == null) {
            try {
                obj = df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
            } catch (VersionException e) {
                throw new ResolveException(409,
                    "Program " + path + " needs a version upgrade; open it in Ghidra first");
            } catch (CancelledException e) {
                throw new ResolveException(500, "Open cancelled: " + path);
            } catch (IOException e) {
                throw new ResolveException(500, "Failed to open " + path + ": " + e.getMessage());
            }
        }
        if (!(obj instanceof Program)) {
            obj.release(this);
            throw new ResolveException(400, "Not a program: " + path);
        }
        Program program = (Program) obj;
        opened.put(path, program);
        program.addCloseListener(dobj -> {
            synchronized (ProgramRegistry.this) {
                opened.remove(path, program);
            }
        });
        Msg.info(this, "GhidraHTTP opened program " + path);
        return program;
    }

    /** The program to use when a request names none. */
    public synchronized Program defaultProgram() {
        // Prefer the active program of a running CodeBrowser (first one with a ProgramManager).
        for (PluginTool t : runningTools()) {
            ProgramManager pm = t.getService(ProgramManager.class);
            if (pm != null) {
                Program p = pm.getCurrentProgram();
                if (p != null) {
                    return p;
                }
            }
        }
        // Otherwise, if we hold exactly one program open, use it.
        opened.values().removeIf(DomainObject::isClosed);
        if (opened.size() == 1) {
            return opened.values().iterator().next();
        }
        return null;
    }

    // ---- running tools ----

    public List<PluginTool> runningTools() {
        List<PluginTool> out = new ArrayList<>();
        ToolServices ts = tool != null ? tool.getToolServices() : null;
        if (ts == null) {
            return out;
        }
        PluginTool[] tools = ts.getRunningTools();
        if (tools != null) {
            for (PluginTool t : tools) {
                if (t != null && t != tool) {
                    out.add(t);
                }
            }
        }
        return out;
    }

    /**
     * Find a running tool that has the program open, preferring one where it is the active
     * program. Returns null if no running tool has it.
     */
    public PluginTool toolFor(Program program) {
        PluginTool fallback = null;
        for (PluginTool t : runningTools()) {
            ProgramManager pm = t.getService(ProgramManager.class);
            if (pm == null) {
                continue;
            }
            if (program == null) {
                return t;
            }
            if (pm.getCurrentProgram() == program) {
                return t;
            }
            if (fallback == null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    if (p == program) {
                        fallback = t;
                        break;
                    }
                }
            }
        }
        return fallback;
    }

    /** All programs open anywhere in this Ghidra session: ours plus every running tool's. */
    public synchronized List<OpenProgram> listOpen() {
        Map<Program, OpenProgram> rows = new LinkedHashMap<>();
        opened.values().removeIf(DomainObject::isClosed);
        for (Program p : opened.values()) {
            rows.put(p, new OpenProgram(p, true));
        }
        for (PluginTool t : runningTools()) {
            ProgramManager pm = t.getService(ProgramManager.class);
            if (pm == null) {
                continue;
            }
            Program current = pm.getCurrentProgram();
            for (Program p : pm.getAllOpenPrograms()) {
                OpenProgram row = rows.computeIfAbsent(p, k -> new OpenProgram(k, false));
                row.tools.add(t.getName());
                if (p == current) {
                    row.activeInTool = true;
                }
            }
        }
        return new ArrayList<>(rows.values());
    }

    // ---- lifecycle ----

    public boolean isOpenedByServer(Program p) {
        synchronized (this) {
            return opened.containsValue(p);
        }
    }

    /**
     * Release the server's hold on a program. If nothing else has it open and it has unsaved
     * changes, refuse unless force is set (the changes would be lost).
     */
    public synchronized void close(String spec, boolean force) throws ResolveException {
        DomainFile df = findFile(spec);
        String path = df.getPathname();
        Program p = opened.get(path);
        if (p == null) {
            throw new ResolveException(404, "Program not opened by the server: " + path);
        }
        boolean lastConsumer = p.getConsumerList().size() <= 1;
        if (lastConsumer && p.isChanged() && !force) {
            throw new ResolveException(409,
                "Program " + path + " has unsaved changes; save it or pass force=true");
        }
        opened.remove(path);
        p.release(this);
        Msg.info(this, "GhidraHTTP released program " + path);
    }

    public void save(Program p) throws ResolveException {
        if (!p.isChanged()) {
            return;
        }
        if (!p.canSave()) {
            throw new ResolveException(409, "Program cannot be saved (read-only or locked): " +
                pathOf(p));
        }
        try {
            p.save("GhidraHTTP save", TaskMonitor.DUMMY);
        } catch (IOException e) {
            throw new ResolveException(500, "Save failed: " + e.getMessage());
        } catch (CancelledException e) {
            throw new ResolveException(500, "Save cancelled");
        }
    }

    /** Release everything we hold. Unsaved changes on programs nobody else has open are lost. */
    public synchronized void releaseAll() {
        for (Program p : new ArrayList<>(opened.values())) {
            try {
                if (!p.isClosed()) {
                    p.release(this);
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to release " + pathOf(p) + ": " + e.getMessage());
            }
        }
        opened.clear();
    }
}
