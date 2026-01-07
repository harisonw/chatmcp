# OAuth 2.0 + PKCE Auto-Discovery for MCP Servers

This feature adds automatic OAuth 2.0 authentication support for remote MCP servers, enabling seamless integration with OAuth-protected services like Notion MCP and Atlassian MCP.

## Features

- **🔍 Auto-Discovery**: Automatically detects OAuth requirements using RFC 8414 (OAuth 2.0 Authorization Server Metadata)
- **🔐 Dynamic Client Registration**: Supports RFC 7591 for automatic client registration when supported by the server
- **🛡️ PKCE Security**: Implements RFC 7636 (Proof Key for Code Exchange) for secure public client authentication
- **🌐 Public Client Support**: Works with servers that don't require client_id (like Notion MCP)
- **🔄 Token Management**: Automatic token refresh and expiry handling
- **🚫 Extension Filtering**: Filters out browser extension interference during OAuth callbacks

## Platform Support

**✅ Web Platform**: Full OAuth support with popup-based authentication flow  
**✅ Desktop (Windows/macOS/Linux)**: Full OAuth support with system browser-based authentication flow  
**❌ Mobile (iOS/Android)**: OAuth authentication is not yet supported on mobile platforms

### Platform-Specific Implementation

#### Web Platform
- Opens OAuth authorization in a popup window
- Uses cross-origin messaging for callback handling
- Returns to the same web application seamlessly

#### Desktop Platform (Windows, macOS, Linux)
- Opens OAuth authorization in the system's default browser
- Runs a local HTTP server on `localhost:8080` to receive the callback
- Displays success/error page in browser after authentication
- Automatically closes the browser window (or prompts user to close)

#### Mobile Platform
- OAuth discovery still works (detects requirements)
- OAuth authentication is not yet implemented
- Future enhancement planned for mobile OAuth support

## Tested OAuth Providers

- ✅ **Notion MCP** (`https://mcp.notion.com/mcp`)
- ✅ **Atlassian MCP** (specific URL varies)
- 🔄 **Other RFC 8414 compliant servers** (should work automatically)

## How It Works

1. **Discovery Phase**: When you enter an MCP server URL, the system:
   - Checks `/.well-known/oauth-authorization-server` for OAuth metadata
   - Attempts dynamic client registration if available
   - Falls back to public client mode if no client registration

2. **Authentication Phase**: 
   - **Web**: Opens OAuth authorization in a popup window
   - **Desktop**: Opens OAuth authorization in the system's default browser
   - Handles PKCE code challenge/verifier generation for security
   - Processes OAuth callback with state validation to prevent CSRF attacks
   - Exchanges authorization code for access token

3. **Usage Phase**:
   - Automatically includes `Authorization: Bearer <token>` in MCP requests
   - Handles token refresh when needed
   - Validates token expiry

## Architecture

### Web Platform
```
┌─────────────────┐    ┌────────────────────┐    ┌─────────────────┐
│   MCP Server    │    │  OAuth Discovery   │    │  OAuth Handler  │
│                 │◄──►│                    │◄──►│   (Web/Popup)   │
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

### Desktop Platform (Windows/macOS/Linux)
```
┌─────────────────┐    ┌────────────────────┐    ┌─────────────────┐
│   MCP Server    │    │  OAuth Discovery   │    │  OAuth Handler  │
│                 │◄──►│                    │◄──►│   (Desktop)     │
│ /.well-known/   │    │ RFC 8414 Compliant │    │ PKCE + Browser  │
│ oauth-auth...   │    │                    │    │ Local Server    │
└─────────────────┘    └────────────────────┘    └─────────────────┘
                                │                         │
                                ▼                         ▼
                       ┌────────────────────┐    ┌─────────────────┐
                       │   MCP Client       │    │ System Browser  │
                       │                    │    │                 │
                       │ Bearer Token Auth  │    │ localhost:8080  │
                       │ StreamableClient   │    │ Callback Server │
                       │ SSEClient          │    │                 │
                       └────────────────────┘    └─────────────────┘
```

## Usage

### Web Platform
1. Go to **Settings → MCP Servers**
2. Enter an OAuth-protected MCP server URL (e.g., `https://mcp.atlassian.com/v1/mcp`)
3. Click **Add Server** - OAuth requirements are detected automatically
4. If OAuth is required, you'll be prompted to authenticate
5. Complete the OAuth flow in the popup window
6. The server will be ready to use with automatic token authentication

### Desktop Platform (Windows/macOS/Linux)
1. Go to **Settings → MCP Servers**
2. Enter an OAuth-protected MCP server URL (e.g., `https://mcp.atlassian.com/v1/mcp`)
3. Click **Add Server** - OAuth requirements are detected automatically
4. If OAuth is required, you'll be prompted to authenticate
5. Your default browser will open to the OAuth provider's authorization page
6. After granting permission, you'll see a success page in the browser
7. Return to ChatMCP - the server will be ready to use with automatic token authentication

## Security Features

- **PKCE Protection**: Prevents authorization code interception attacks
- **State Parameter Validation**: Prevents CSRF attacks
- **Origin Validation**: Ensures callbacks come from expected sources (web)
- **Browser Extension Filtering**: Ignores interference from development tools (web)
- **Localhost Binding**: Local callback server binds only to localhost for security (desktop)
- **Token Expiry Handling**: Automatic refresh before expiration

## Future Enhancements

- ✅ ~~Desktop OAuth support via external browser~~ (Implemented in this version)
- Mobile OAuth support (iOS/Android)
- Additional OAuth flows (device code, client credentials, etc.)
- OAuth provider-specific optimizations
- Enhanced error handling and user feedback
- Configurable callback server port for desktop

---

## Implementation Notes

### Platform-Specific OAuth Handlers

The OAuth implementation uses Dart's conditional imports to provide platform-specific handlers:

- **Web Platform** (`oauth_web.dart`): Uses popup windows and `postMessage` API for callback handling
- **Desktop Platform** (`oauth_io.dart`): Uses `url_launcher` to open system browser and runs a local HTTP server on `localhost:8080` for callbacks
- **Stub** (`oauth_stub.dart`): Placeholder for unsupported platforms (currently mobile)

### File Structure

- `lib/utils/oauth_discovery.dart`: Platform-agnostic OAuth discovery service (RFC 8414, RFC 7591)
- `lib/utils/oauth_web.dart`: Web-specific OAuth handler
- `lib/utils/oauth_io.dart`: Desktop-specific OAuth handler (Windows/macOS/Linux)
- `lib/utils/oauth_stub.dart`: Stub for unsupported platforms
- `lib/provider/mcp_server_provider.dart`: OAuth integration with MCP server management
- `web/oauth_callback.html`: OAuth callback page for web platform

This implementation follows OAuth 2.0 security best practices and modern web standards for a robust, user-friendly authentication experience across multiple platforms.
