# OAuth 2.0 + PKCE Auto-Discovery for MCP Servers

This feature adds automatic OAuth 2.0 authentication support for remote MCP servers, enabling seamless integration with OAuth-protected services like Notion MCP and Atlassian MCP.

## Features

- **🔍 Auto-Discovery**: Automatically detects OAuth requirements using RFC 8414 (OAuth 2.0 Authorization Server Metadata)
- **🔐 Dynamic Client Registration**: Supports RFC 7591 for automatic client registration when supported by the server
- **🛡️ PKCE Security**: Implements RFC 7636 (Proof Key for Code Exchange) for secure public client authentication
- **🌐 Public Client Support**: Works with servers that don't require client_id (like Notion MCP)
- **🔄 Token Management**: Automatic token refresh and expiry handling
- **🚫 Extension Filtering**: Filters out browser extension interference during OAuth callbacks (web)
- **🖥️ Desktop Support**: Full OAuth support for Windows, macOS, and Linux desktop applications

## Platform Support

**✅ Web Platform**: Full OAuth support with popup-based authentication flow  
**✅ Desktop Platform** (Windows, macOS, Linux): Full OAuth support with external browser and local callback server  
**❌ Mobile**: OAuth authentication is not yet supported on mobile platforms

On desktop platforms:
- OAuth discovery works automatically
- OAuth authentication opens external browser for user authorization
- Local HTTP server handles OAuth callback securely
- Same PKCE security as web implementation

## Tested OAuth Providers

- ✅ **Notion MCP** (`https://mcp.notion.com/mcp`)
- ✅ **Atlassian MCP** (`https://mcp.atlassian.com/v1/mcp`)
- 🔄 **Other RFC 8414 compliant servers** (should work automatically)

## How It Works

### Web Platform

1. **Discovery Phase**: When you enter an MCP server URL, the system:
   - Checks `/.well-known/oauth-authorization-server` for OAuth metadata
   - Attempts dynamic client registration if available
   - Falls back to public client mode if no client registration

2. **Authentication Phase**: 
   - Opens OAuth authorization popup
   - Handles PKCE code challenge/verifier generation
   - Processes OAuth callback with state validation
   - Exchanges authorization code for access token

3. **Usage Phase**:
   - Automatically includes `Authorization: Bearer <token>` in MCP requests
   - Handles token refresh when needed
   - Validates token expiry

### Desktop Platform (Windows, macOS, Linux)

1. **Discovery Phase**: Same as web platform

2. **Authentication Phase**: 
   - Starts local HTTP callback server on available port
   - Opens system default browser for OAuth authorization
   - Handles PKCE code challenge/verifier generation
   - Receives OAuth callback via local server with state validation
   - Exchanges authorization code for access token
   - Automatically closes local server after completion

3. **Usage Phase**: Same as web platform

## Architecture

### Web Platform
```
┌─────────────────┐    ┌────────────────────┐    ┌─────────────────┐
│   MCP Server    │    │  OAuth Discovery   │    │  OAuth Handler  │
│                 │◄──►│                    │◄──►│                 │
│ /.well-known/   │    │ RFC 8414 Compliant │    │ PKCE + Popup    │
│ oauth-auth...   │    │                    │    │ Cross-origin    │
└─────────────────┘    └────────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌────────────────────┐
                       │   MCP Client       │
                       │                    │
                       │ Bearer Token Auth  │
                       │ StreamableClient   │
                       │ SSEClient          │
                       └────────────────────┘
```

### Desktop Platform
```
┌─────────────────┐    ┌────────────────────┐    ┌─────────────────┐
│   MCP Server    │    │  OAuth Discovery   │    │  OAuth Handler  │
│                 │◄──►│                    │◄──►│                 │
│ /.well-known/   │    │ RFC 8414 Compliant │    │ PKCE + Browser  │
│ oauth-auth...   │    │                    │    │ Local Server    │
└─────────────────┘    └────────────────────┘    └─────────────────┘
                                │                         │
                                ▼                         ▼
                       ┌────────────────────┐    ┌─────────────────┐
                       │   MCP Client       │    │ HTTP Server     │
                       │                    │    │ localhost:port  │
                       │ Bearer Token Auth  │    │ OAuth Callback  │
                       │ StreamableClient   │    │                 │
                       │ SSEClient          │    │                 │
                       └────────────────────┘    └─────────────────┘
```

## Usage

1. Go to **Settings → MCP Servers**
2. Enter an OAuth-protected MCP server URL (e.g., `https://mcp.notion.com/mcp`)
3. Click **Add Server** - OAuth requirements are detected automatically
4. If OAuth is required, you'll be prompted to authenticate
5. Complete the OAuth flow in the popup window
6. The server will be ready to use with automatic token authentication

## Security Features

- **PKCE Protection**: Prevents authorization code interception attacks
- **State Parameter Validation**: Prevents CSRF attacks
- **Origin Validation**: Ensures callbacks come from expected sources (web)
- **Local Server Security**: Uses localhost-only binding for OAuth callbacks (desktop)
- **Browser Extension Filtering**: Ignores interference from development tools (web)
- **Token Expiry Handling**: Automatic refresh before expiration

## Future Enhancements

- Mobile OAuth support via external browser
- Additional OAuth flows (device code, etc.)
- OAuth provider-specific optimizations
- Enhanced error handling and user feedback

---

This implementation follows OAuth 2.0 security best practices and modern web standards for a robust, user-friendly authentication experience.
