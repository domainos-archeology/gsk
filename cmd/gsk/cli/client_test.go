package cli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testServer creates a test HTTP server that returns the specified response
func testServer(t *testing.T, expectedPath string, response string, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectedPath != "" && !strings.HasPrefix(r.URL.String(), expectedPath) {
			t.Errorf("unexpected path: got %s, want prefix %s", r.URL.String(), expectedPath)
		}
		w.WriteHeader(statusCode)
		w.Write([]byte(response))
	}))
}

// testServerWithHandler creates a test server with a custom handler
func testServerWithHandler(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// clientFromTestServer creates a GhidraClient pointing to the test server
func clientFromTestServer(ts *httptest.Server) *GhidraClient {
	// Strip the http:// prefix since NewGhidraClient adds it
	server := strings.TrimPrefix(ts.URL, "http://")
	return NewGhidraClient(server)
}

func TestNewGhidraClient(t *testing.T) {
	client := NewGhidraClient("localhost:8080")
	if client.baseURL != "http://localhost:8080" {
		t.Errorf("baseURL = %s, want http://localhost:8080", client.baseURL)
	}
	if client.http == nil {
		t.Error("http client is nil")
	}
}

func TestDecompileFunction(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		response   string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "success",
			address:    "0x401234",
			response:   "int main() { return 0; }",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "server error",
			address:    "0x401234",
			response:   "Error: No program loaded",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    false, // HTTP errors are not returned as Go errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := testServer(t, "/decompile_function", tt.response, tt.statusCode)
			defer ts.Close()

			client := clientFromTestServer(ts)
			got, err := client.DecompileFunction(tt.address)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecompileFunction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.response {
				t.Errorf("DecompileFunction() = %s, want %s", got, tt.response)
			}
		})
	}
}

func TestDecompileFunctionURLConstruction(t *testing.T) {
	var capturedURL string
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	client.DecompileFunction("0x401234")

	expected := "/decompile_function?address=0x401234"
	if capturedURL != expected {
		t.Errorf("URL = %s, want %s", capturedURL, expected)
	}
}

func TestDisassembleFunction(t *testing.T) {
	response := "; Function: main\n0x401234    push ebp"
	ts := testServer(t, "/disassemble_function", response, http.StatusOK)
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.DisassembleFunction("0x401234")
	if err != nil {
		t.Fatalf("DisassembleFunction() error = %v", err)
	}
	if string(got) != response {
		t.Errorf("DisassembleFunction() = %s, want %s", got, response)
	}
}

func TestGetFunctionByAddress(t *testing.T) {
	response := "Name: main\nEntry: 0x401234"
	ts := testServer(t, "/get_function_by_address", response, http.StatusOK)
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.GetFunctionByAddress("0x401234")
	if err != nil {
		t.Fatalf("GetFunctionByAddress() error = %v", err)
	}
	if string(got) != response {
		t.Errorf("GetFunctionByAddress() = %s, want %s", got, response)
	}
}

func TestGetCurrentFunction(t *testing.T) {
	response := "Name: current_func\nEntry: 0x401000"
	ts := testServer(t, "/get_current_function", response, http.StatusOK)
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.GetCurrentFunction()
	if err != nil {
		t.Fatalf("GetCurrentFunction() error = %v", err)
	}
	if string(got) != response {
		t.Errorf("GetCurrentFunction() = %s, want %s", got, response)
	}
}

func TestGetCurrentAddress(t *testing.T) {
	response := "0x401234"
	ts := testServer(t, "/get_current_address", response, http.StatusOK)
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.GetCurrentAddress()
	if err != nil {
		t.Fatalf("GetCurrentAddress() error = %v", err)
	}
	if string(got) != response {
		t.Errorf("GetCurrentAddress() = %s, want %s", got, response)
	}
}

func TestListFunctions(t *testing.T) {
	response := "0x401000\tmain\n0x401100\thelper"
	ts := testServer(t, "/list_functions", response, http.StatusOK)
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.ListFunctions()
	if err != nil {
		t.Fatalf("ListFunctions() error = %v", err)
	}
	if string(got) != response {
		t.Errorf("ListFunctions() = %s, want %s", got, response)
	}
}

func TestXrefsTo(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		limit    int
		wantPath string
	}{
		{
			name:     "default limit",
			address:  "0x401234",
			limit:    100,
			wantPath: "/xrefs_to?address=0x401234&limit=100",
		},
		{
			name:     "custom limit",
			address:  "0x401234",
			limit:    50,
			wantPath: "/xrefs_to?address=0x401234&limit=50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedURL string
			ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
				capturedURL = r.URL.String()
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("0x401000 -> 0x401234 (CALL)"))
			})
			defer ts.Close()

			client := clientFromTestServer(ts)
			_, err := client.XrefsTo(tt.address, tt.limit)
			if err != nil {
				t.Fatalf("XrefsTo() error = %v", err)
			}
			if capturedURL != tt.wantPath {
				t.Errorf("URL = %s, want %s", capturedURL, tt.wantPath)
			}
		})
	}
}

func TestXrefsFrom(t *testing.T) {
	var capturedURL string
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("0x401234 -> 0x401500 (CALL)"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	_, err := client.XrefsFrom("0x401234", 100)
	if err != nil {
		t.Fatalf("XrefsFrom() error = %v", err)
	}

	expected := "/xrefs_from?address=0x401234&limit=100"
	if capturedURL != expected {
		t.Errorf("URL = %s, want %s", capturedURL, expected)
	}
}

func TestStrings(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		limit    int
		wantPath string
	}{
		{
			name:     "no filter",
			filter:   "",
			limit:    100,
			wantPath: "/strings?limit=100",
		},
		{
			name:     "with filter",
			filter:   "password",
			limit:    50,
			wantPath: "/strings?limit=50&filter=password",
		},
		{
			name:     "filter with special chars",
			filter:   "hello world",
			limit:    100,
			wantPath: "/strings?limit=100&filter=hello+world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedURL string
			ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
				capturedURL = r.URL.String()
				w.WriteHeader(http.StatusOK)
			})
			defer ts.Close()

			client := clientFromTestServer(ts)
			_, err := client.Strings(tt.filter, tt.limit)
			if err != nil {
				t.Fatalf("Strings() error = %v", err)
			}
			if capturedURL != tt.wantPath {
				t.Errorf("URL = %s, want %s", capturedURL, tt.wantPath)
			}
		})
	}
}

func TestSearchFunctions(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		limit    int
		wantPath string
	}{
		{
			name:     "simple query",
			query:    "main",
			limit:    100,
			wantPath: "/searchFunctions?query=main&limit=100",
		},
		{
			name:     "query with spaces",
			query:    "get data",
			limit:    50,
			wantPath: "/searchFunctions?query=get+data&limit=50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedURL string
			ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
				capturedURL = r.URL.String()
				w.WriteHeader(http.StatusOK)
			})
			defer ts.Close()

			client := clientFromTestServer(ts)
			_, err := client.SearchFunctions(tt.query, tt.limit)
			if err != nil {
				t.Fatalf("SearchFunctions() error = %v", err)
			}
			if capturedURL != tt.wantPath {
				t.Errorf("URL = %s, want %s", capturedURL, tt.wantPath)
			}
		})
	}
}

func TestChangesSince(t *testing.T) {
	var capturedURL string
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[1704723456] symbol_renamed at 0x401234"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	_, err := client.ChangesSince(1704723456000, 100)
	if err != nil {
		t.Fatalf("ChangesSince() error = %v", err)
	}

	expected := "/changes_since?since=1704723456000&limit=100"
	if capturedURL != expected {
		t.Errorf("URL = %s, want %s", capturedURL, expected)
	}
}

func TestSetFunctionPrototype(t *testing.T) {
	var capturedBody string
	var capturedContentType string
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		capturedContentType = r.Header.Get("Content-Type")
		body, _ := url.ParseQuery(readBody(r))
		capturedBody = body.Get("function_address") + ":" + body.Get("prototype")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Prototype updated"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.SetFunctionPrototype("0x401234", "int main(int argc, char **argv)")
	if err != nil {
		t.Fatalf("SetFunctionPrototype() error = %v", err)
	}
	if string(got) != "Prototype updated" {
		t.Errorf("SetFunctionPrototype() = %s, want Prototype updated", got)
	}
	if capturedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %s, want application/x-www-form-urlencoded", capturedContentType)
	}
	if capturedBody != "0x401234:int main(int argc, char **argv)" {
		t.Errorf("Body = %s, want 0x401234:int main(int argc, char **argv)", capturedBody)
	}
}

func TestRenameFunction(t *testing.T) {
	var capturedBody url.Values
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		capturedBody, _ = url.ParseQuery(readBody(r))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Function renamed"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.RenameFunction("0x401234", "new_function_name")
	if err != nil {
		t.Fatalf("RenameFunction() error = %v", err)
	}
	if string(got) != "Function renamed" {
		t.Errorf("RenameFunction() = %s, want Function renamed", got)
	}
	if capturedBody.Get("function_address") != "0x401234" {
		t.Errorf("function_address = %s, want 0x401234", capturedBody.Get("function_address"))
	}
	if capturedBody.Get("new_name") != "new_function_name" {
		t.Errorf("new_name = %s, want new_function_name", capturedBody.Get("new_name"))
	}
}

func TestSetLocalVariableType(t *testing.T) {
	var capturedBody url.Values
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = url.ParseQuery(readBody(r))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Variable type updated"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.SetLocalVariableType("0x401234", "param_1", "char *")
	if err != nil {
		t.Fatalf("SetLocalVariableType() error = %v", err)
	}
	if string(got) != "Variable type updated" {
		t.Errorf("SetLocalVariableType() = %s, want Variable type updated", got)
	}
	if capturedBody.Get("function_address") != "0x401234" {
		t.Errorf("function_address = %s, want 0x401234", capturedBody.Get("function_address"))
	}
	if capturedBody.Get("variable_name") != "param_1" {
		t.Errorf("variable_name = %s, want param_1", capturedBody.Get("variable_name"))
	}
	if capturedBody.Get("new_type") != "char *" {
		t.Errorf("new_type = %s, want char *", capturedBody.Get("new_type"))
	}
}

func TestSetDecompilerComment(t *testing.T) {
	var capturedBody url.Values
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = url.ParseQuery(readBody(r))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Comment set"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.SetDecompilerComment("0x401234", "This is a test comment")
	if err != nil {
		t.Fatalf("SetDecompilerComment() error = %v", err)
	}
	if string(got) != "Comment set" {
		t.Errorf("SetDecompilerComment() = %s, want Comment set", got)
	}
	if capturedBody.Get("address") != "0x401234" {
		t.Errorf("address = %s, want 0x401234", capturedBody.Get("address"))
	}
	if capturedBody.Get("comment") != "This is a test comment" {
		t.Errorf("comment = %s, want This is a test comment", capturedBody.Get("comment"))
	}
}

func TestSetDisassemblyComment(t *testing.T) {
	var capturedBody url.Values
	ts := testServerWithHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = url.ParseQuery(readBody(r))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Comment set"))
	})
	defer ts.Close()

	client := clientFromTestServer(ts)
	got, err := client.SetDisassemblyComment("0x401234", "EOL comment")
	if err != nil {
		t.Fatalf("SetDisassemblyComment() error = %v", err)
	}
	if string(got) != "Comment set" {
		t.Errorf("SetDisassemblyComment() = %s, want Comment set", got)
	}
	if capturedBody.Get("address") != "0x401234" {
		t.Errorf("address = %s, want 0x401234", capturedBody.Get("address"))
	}
	if capturedBody.Get("comment") != "EOL comment" {
		t.Errorf("comment = %s, want EOL comment", capturedBody.Get("comment"))
	}
}

func TestNetworkError(t *testing.T) {
	// Test with invalid server address
	client := NewGhidraClient("localhost:99999")
	_, err := client.DecompileFunction("0x401234")
	if err == nil {
		t.Error("expected network error, got nil")
	}
}

// Helper function to read request body
func readBody(r *http.Request) string {
	body := make([]byte, r.ContentLength)
	r.Body.Read(body)
	return string(body)
}
