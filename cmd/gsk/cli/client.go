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

// newClient creates a GhidraClient using the configured server address.
func newClient() *GhidraClient {
	return NewGhidraClient(getGhidraServer())
}
