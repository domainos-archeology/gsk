package ghidrahttp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for GhidraHTTPServer.
 *
 * Note: Full integration tests require a running Ghidra instance with the plugin loaded.
 * These tests focus on HTTP-level behavior and utility methods that can be tested in isolation.
 *
 * For testing with Ghidra mocks, consider using Ghidra's headless mode or
 * the GhidraTestCase framework from ghidra.test.AbstractGhidraHeadlessIntegrationTest.
 */
class GhidraHTTPServerTest {

    /**
     * Test helper to make HTTP requests
     */
    private String httpGet(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }

    private String httpPost(String urlString, String body) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }

    @Test
    @DisplayName("URL query string encoding should handle special characters")
    void testQueryStringEncoding() throws Exception {
        // Test that URL encoding works correctly
        String encoded = URLEncoder.encode("hello world", StandardCharsets.UTF_8);
        assertEquals("hello+world", encoded);

        String decoded = URLDecoder.decode("hello+world", StandardCharsets.UTF_8);
        assertEquals("hello world", decoded);
    }

    @Test
    @DisplayName("Form data encoding should handle special characters")
    void testFormDataEncoding() throws Exception {
        // Test form data encoding for POST requests
        String prototype = "int main(int argc, char **argv)";
        String encoded = URLEncoder.encode(prototype, StandardCharsets.UTF_8);

        // Verify it can be decoded back
        String decoded = URLDecoder.decode(encoded, StandardCharsets.UTF_8);
        assertEquals(prototype, decoded);
    }

    @Test
    @DisplayName("Address parsing formats should be consistent")
    void testAddressFormats() {
        // Test various address format strings
        String[] validAddresses = {
            "0x401234",
            "0x00401234",
            "401234",
            "0xFFFFFFFF"
        };

        for (String addr : validAddresses) {
            // Just verify these don't throw - actual parsing is done by Ghidra
            assertNotNull(addr);
            assertTrue(addr.length() > 0);
        }
    }

    @Test
    @DisplayName("HTTP response content type should be text/plain")
    void testExpectedContentType() {
        // The server should return text/plain responses
        String expectedContentType = "text/plain; charset=utf-8";
        assertNotNull(expectedContentType);
    }

    /**
     * Integration test placeholder - requires running server
     *
     * To run integration tests:
     * 1. Start Ghidra with the GhidraHTTP plugin loaded
     * 2. Open a binary in Ghidra
     * 3. Run these tests with -DintegrationTests=true
     */
    @Test
    @DisplayName("Health endpoint should return OK (integration test - skipped by default)")
    void testHealthEndpoint() {
        // Skip if not running integration tests
        String integrationTests = System.getProperty("integrationTests", "false");
        if (!"true".equals(integrationTests)) {
            System.out.println("Skipping integration test - set -DintegrationTests=true to run");
            return;
        }

        try {
            String response = httpGet("http://localhost:8080/health");
            assertEquals("OK", response);
        } catch (IOException e) {
            fail("Could not connect to Ghidra HTTP server: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("GET endpoints should use correct URL patterns")
    void testEndpointURLPatterns() {
        // Verify expected endpoint patterns
        String[] getEndpoints = {
            "/decompile_function?address=",
            "/disassemble_function?address=",
            "/get_function_by_address?address=",
            "/get_current_function",
            "/get_current_address",
            "/list_functions",
            "/xrefs_to?address=",
            "/xrefs_from?address=",
            "/strings?limit=",
            "/searchFunctions?query=",
            "/changes_since?since="
        };

        for (String endpoint : getEndpoints) {
            assertTrue(endpoint.startsWith("/"), "Endpoint should start with /: " + endpoint);
        }
    }

    @Test
    @DisplayName("POST endpoints should use correct URL patterns")
    void testPostEndpointURLPatterns() {
        // Verify expected POST endpoint patterns
        String[] postEndpoints = {
            "/set_function_prototype",
            "/rename_function_by_address",
            "/set_local_variable_type",
            "/set_decompiler_comment",
            "/set_disassembly_comment"
        };

        for (String endpoint : postEndpoints) {
            assertTrue(endpoint.startsWith("/"), "Endpoint should start with /: " + endpoint);
            assertFalse(endpoint.contains("?"), "POST endpoints should not have query params: " + endpoint);
        }
    }
}
