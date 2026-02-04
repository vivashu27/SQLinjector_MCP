# SQL Injection MCP Server

A Model Context Protocol (MCP) server for discovering SQL injection vulnerabilities in web applications.

## Features

- **Multiple Injection Types**: Error-based, Time-based, Boolean-based, Union-based, Blind SQL injection
- **Database Support**: MySQL, MSSQL, PostgreSQL, Oracle, SQLite
- **HTTP Methods**: GET and POST parameter testing
- **Authentication**: Custom headers, cookies, Bearer tokens
- **Proxy Support**: Route traffic through Burp Suite or other proxies
- **WAF Bypass**: URL encoding, Hex encoding, Unicode, Case swapping, Comment injection
- **Custom Payloads**: Load payloads from external files

## Installation

```bash
# Using uv (recommended)
cd SQLinjector_MCP
uv sync

# Using pip
pip install -e .
```

## Usage

### Running the Server

```bash
# Using uv
uv run sqli-mcp

# Or directly
python -m sqli_mcp.server
```

### MCP Client Configuration

#### Claude Desktop / Claude Code

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "sqli-scanner": {
      "command": "uv",
      "args": ["--directory", "C:/path/to/SQLinjector_MCP", "run", "sqli-mcp"]
    }
  }
}
```

#### LM Studio / Cursor

Configure the server URL after starting with HTTP transport:

```bash
uv run python -c "from sqli_mcp.server import mcp; mcp.run(transport='streamable-http')"
```

Then connect to `http://localhost:8000/mcp`

## Available Tools

| Tool | Description |
|------|-------------|
| `scan_url` | Full URL scan for SQLi in all detected parameters |
| `scan_get_parameter` | Test specific GET parameter |
| `scan_post_parameter` | Test specific POST parameter |
| `test_payload` | Test a single payload against a target |
| `list_payloads` | List available built-in payloads |
| `load_custom_payloads_from_file` | Load payloads from external file |
| `get_waf_bypass_payloads` | Get WAF bypass variants of a payload |
| `get_scan_result` | Retrieve previous scan results |

## Examples

### Basic GET Parameter Scan

```
Use scan_url with:
- target_url: "http://vulnerable-site.com/page?id=1"
```

### Authenticated POST Scan

```
Use scan_post_parameter with:
- target_url: "http://site.com/login"
- post_data: "username=admin&password=test"
- parameter: "username"
- cookies: "session=abc123"
- bearer_token: "your-jwt-token"
```

### Using Burp Suite Proxy

```
Use scan_url with:
- target_url: "http://target.com/page?id=1"
- proxy_url: "http://127.0.0.1:8080"
- verify_ssl: false
```

### WAF Bypass

```
Use scan_url with:
- target_url: "http://target.com/page?id=1"
- waf_bypass: "comment_injection"
```

## Custom Payloads

Create a text file with one payload per line:

```text
# my_payloads.txt
' OR '1'='1
" OR "1"="1
' UNION SELECT NULL--
```

Then load with:
```
Use load_custom_payloads_from_file with:
- file_path: "C:/path/to/my_payloads.txt"
- injection_type: "union_based"
- name: "my_custom"
```

## Security Notice

⚠️ **This tool is intended for authorized security testing only.** Always obtain proper authorization before testing any system for vulnerabilities. Unauthorized access to computer systems is illegal.

## License

MIT
