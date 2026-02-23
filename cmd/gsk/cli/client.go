package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GhidraClient provides methods for interacting with the Ghidra HTTP API.
type GhidraClient struct {
	baseURL string
	http    *http.Client
}

// NewGhidraClient creates a new client for the given server address.
func NewGhidraClient(server string) *GhidraClient {
	return &GhidraClient{
		baseURL: fmt.Sprintf("http://%s", server),
		http:    &http.Client{},
	}
}

// get performs a GET request and returns the response body.
func (c *GhidraClient) get(endpoint string) ([]byte, error) {
	resp, err := c.http.Get(c.baseURL + endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// post performs a POST request with form data and returns the response body.
func (c *GhidraClient) post(endpoint string, data url.Values) ([]byte, error) {
	resp, err := c.http.Post(
		c.baseURL+endpoint,
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// DecompileFunction returns decompiled C pseudocode for the function at the given address.
func (c *GhidraClient) DecompileFunction(address string) ([]byte, error) {
	return c.get(fmt.Sprintf("/decompile_function?address=%s", address))
}

// DisassembleFunction returns assembly code for the function at the given address.
func (c *GhidraClient) DisassembleFunction(address string) ([]byte, error) {
	return c.get(fmt.Sprintf("/disassemble_function?address=%s", address))
}

// GetFunctionByAddress returns function information for the given address.
func (c *GhidraClient) GetFunctionByAddress(address string) ([]byte, error) {
	return c.get(fmt.Sprintf("/get_function_by_address?address=%s", address))
}

// GetCurrentFunction returns the currently selected function in Ghidra.
func (c *GhidraClient) GetCurrentFunction() ([]byte, error) {
	return c.get("/get_current_function")
}

// GetCurrentAddress returns the current cursor address in Ghidra.
func (c *GhidraClient) GetCurrentAddress() ([]byte, error) {
	return c.get("/get_current_address")
}

// ListFunctions returns all functions in the program.
func (c *GhidraClient) ListFunctions() ([]byte, error) {
	return c.get("/list_functions")
}

// XrefsTo returns cross-references to the given address.
func (c *GhidraClient) XrefsTo(address string, limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/xrefs_to?address=%s&limit=%d", address, limit))
}

// XrefsFrom returns cross-references from the given address.
func (c *GhidraClient) XrefsFrom(address string, limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/xrefs_from?address=%s&limit=%d", address, limit))
}

// Strings returns defined strings, optionally filtered.
func (c *GhidraClient) Strings(filter string, limit int) ([]byte, error) {
	endpoint := fmt.Sprintf("/strings?limit=%d", limit)
	if filter != "" {
		endpoint += fmt.Sprintf("&filter=%s", url.QueryEscape(filter))
	}
	return c.get(endpoint)
}

// SearchFunctions searches for functions by name.
func (c *GhidraClient) SearchFunctions(query string, limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/searchFunctions?query=%s&limit=%d", url.QueryEscape(query), limit))
}

// ChangesSince returns changes made since the given timestamp.
func (c *GhidraClient) ChangesSince(since int64, limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/changes_since?since=%d&limit=%d", since, limit))
}

// SetFunctionPrototype sets the function signature at the given address.
func (c *GhidraClient) SetFunctionPrototype(address, prototype string) ([]byte, error) {
	data := url.Values{}
	data.Set("function_address", address)
	data.Set("prototype", prototype)
	return c.post("/set_function_prototype", data)
}

// RenameFunction renames the function at the given address.
func (c *GhidraClient) RenameFunction(address, newName string) ([]byte, error) {
	data := url.Values{}
	data.Set("function_address", address)
	data.Set("new_name", newName)
	return c.post("/rename_function_by_address", data)
}

// SetLocalVariableType sets the type of a local variable in a function.
func (c *GhidraClient) SetLocalVariableType(functionAddr, varName, newType string) ([]byte, error) {
	data := url.Values{}
	data.Set("function_address", functionAddr)
	data.Set("variable_name", varName)
	data.Set("new_type", newType)
	return c.post("/set_local_variable_type", data)
}

// SetDecompilerComment sets a PRE comment at the given address.
func (c *GhidraClient) SetDecompilerComment(address, comment string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("comment", comment)
	return c.post("/set_decompiler_comment", data)
}

// SetDisassemblyComment sets an EOL comment at the given address.
func (c *GhidraClient) SetDisassemblyComment(address, comment string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("comment", comment)
	return c.post("/set_disassembly_comment", data)
}

// Type-related methods

// ListTypes returns all data types in the program.
func (c *GhidraClient) ListTypes(category string, limit int) ([]byte, error) {
	endpoint := fmt.Sprintf("/list_types?limit=%d", limit)
	if category != "" {
		endpoint += fmt.Sprintf("&category=%s", url.QueryEscape(category))
	}
	return c.get(endpoint)
}

// GetType returns detailed information about a specific type.
func (c *GhidraClient) GetType(name string) ([]byte, error) {
	return c.get(fmt.Sprintf("/get_type?name=%s", url.QueryEscape(name)))
}

// SearchTypes searches for types by name.
func (c *GhidraClient) SearchTypes(query string, limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/search_types?query=%s&limit=%d", url.QueryEscape(query), limit))
}

// CreateType creates a new data type.
func (c *GhidraClient) CreateType(name, kind, definition string) ([]byte, error) {
	data := url.Values{}
	data.Set("name", name)
	data.Set("kind", kind)
	if definition != "" {
		data.Set("definition", definition)
	}
	return c.post("/create_type", data)
}

// UpdateType updates an existing data type.
func (c *GhidraClient) UpdateType(name, newName, definition string) ([]byte, error) {
	data := url.Values{}
	data.Set("name", name)
	if newName != "" {
		data.Set("new_name", newName)
	}
	if definition != "" {
		data.Set("definition", definition)
	}
	return c.post("/update_type", data)
}

// Equate-related methods

// ListEquates returns all equates in the program.
func (c *GhidraClient) ListEquates(limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/list_equates?limit=%d", limit))
}

// GetEquate returns detailed information about a specific equate.
func (c *GhidraClient) GetEquate(name string) ([]byte, error) {
	return c.get(fmt.Sprintf("/get_equate?name=%s", url.QueryEscape(name)))
}

// GetEquateByValue returns the equate with the given value.
func (c *GhidraClient) GetEquateByValue(value string) ([]byte, error) {
	return c.get(fmt.Sprintf("/get_equate?value=%s", url.QueryEscape(value)))
}

// SetEquate creates or updates an equate.
func (c *GhidraClient) SetEquate(name, value, address string, operand int) ([]byte, error) {
	data := url.Values{}
	data.Set("name", name)
	data.Set("value", value)
	if address != "" {
		data.Set("address", address)
		data.Set("operand", fmt.Sprintf("%d", operand))
	}
	return c.post("/set_equate", data)
}

// DeleteEquate deletes an equate or removes a reference.
func (c *GhidraClient) DeleteEquate(name, address string, operand int) ([]byte, error) {
	data := url.Values{}
	data.Set("name", name)
	if address != "" {
		data.Set("address", address)
		data.Set("operand", fmt.Sprintf("%d", operand))
	}
	return c.post("/delete_equate", data)
}

// Label-related methods

// ListLabels returns all labels in the program, optionally at a specific address.
func (c *GhidraClient) ListLabels(address string, limit int) ([]byte, error) {
	endpoint := fmt.Sprintf("/list_labels?limit=%d", limit)
	if address != "" {
		endpoint += fmt.Sprintf("&address=%s", address)
	}
	return c.get(endpoint)
}

// SetLabel creates a label at the given address.
func (c *GhidraClient) SetLabel(address, name, scope string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("name", name)
	if scope != "" {
		data.Set("scope", scope)
	}
	return c.post("/set_label", data)
}

// DeleteLabel removes a label at the given address.
func (c *GhidraClient) DeleteLabel(address, name string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("name", name)
	return c.post("/delete_label", data)
}

// Memory-related methods

// ReadMemory reads bytes from memory at the given address.
func (c *GhidraClient) ReadMemory(address string, length int) ([]byte, error) {
	return c.get(fmt.Sprintf("/read_memory?address=%s&length=%d", address, length))
}

// Data type assignment methods

// GetData returns information about data at the given address.
func (c *GhidraClient) GetData(address string) ([]byte, error) {
	return c.get(fmt.Sprintf("/get_data?address=%s", address))
}

// SetDataType assigns a data type to the given address.
func (c *GhidraClient) SetDataType(address, typeName string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("type", typeName)
	return c.post("/set_data_type", data)
}

// ClearData clears defined data at the given address.
func (c *GhidraClient) ClearData(address string, length int) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	if length > 0 {
		data.Set("length", fmt.Sprintf("%d", length))
	}
	return c.post("/clear_data", data)
}

// Namespace-related methods

// ListNamespaces returns all namespaces in the program.
func (c *GhidraClient) ListNamespaces(limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/list_namespaces?limit=%d", limit))
}

// Class-related methods

// ListClasses returns all classes in the program.
func (c *GhidraClient) ListClasses(limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/list_classes?limit=%d", limit))
}

// Import-related methods

// ListImports returns imported (external) symbols in the program.
func (c *GhidraClient) ListImports(filter string, limit int) ([]byte, error) {
	endpoint := fmt.Sprintf("/list_imports?limit=%d", limit)
	if filter != "" {
		endpoint += fmt.Sprintf("&filter=%s", url.QueryEscape(filter))
	}
	return c.get(endpoint)
}

// Export-related methods

// ListExports returns exported entry points in the program.
func (c *GhidraClient) ListExports(filter string, limit int) ([]byte, error) {
	endpoint := fmt.Sprintf("/list_exports?limit=%d", limit)
	if filter != "" {
		endpoint += fmt.Sprintf("&filter=%s", url.QueryEscape(filter))
	}
	return c.get(endpoint)
}

// Program info and memory map methods

// GetProgramInfo returns program metadata.
func (c *GhidraClient) GetProgramInfo() ([]byte, error) {
	return c.get("/program_info")
}

// ListMemoryBlocks returns memory block information.
func (c *GhidraClient) ListMemoryBlocks(limit int) ([]byte, error) {
	return c.get(fmt.Sprintf("/list_memory_blocks?limit=%d", limit))
}

// Bookmark-related methods

// ListBookmarks returns bookmarks, optionally filtered by type.
func (c *GhidraClient) ListBookmarks(bookmarkType string, limit int) ([]byte, error) {
	endpoint := fmt.Sprintf("/list_bookmarks?limit=%d", limit)
	if bookmarkType != "" {
		endpoint += fmt.Sprintf("&type=%s", url.QueryEscape(bookmarkType))
	}
	return c.get(endpoint)
}

// SetBookmark creates or updates a bookmark at the given address.
func (c *GhidraClient) SetBookmark(address, bookmarkType, category, comment string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("type", bookmarkType)
	if category != "" {
		data.Set("category", category)
	}
	if comment != "" {
		data.Set("comment", comment)
	}
	return c.post("/set_bookmark", data)
}

// DeleteBookmark removes a bookmark at the given address.
func (c *GhidraClient) DeleteBookmark(address, bookmarkType, category string) ([]byte, error) {
	data := url.Values{}
	data.Set("address", address)
	data.Set("type", bookmarkType)
	if category != "" {
		data.Set("category", category)
	}
	return c.post("/delete_bookmark", data)
}

// newClient creates a GhidraClient using the configured server address.
func newClient() *GhidraClient {
	return NewGhidraClient(getGhidraServer())
}
