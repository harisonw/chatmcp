import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

/// Desktop (IO) OAuth 2.0 + PKCE handler for MCP servers
/// 
/// Handles OAuth authorization flows on desktop platforms (Windows, macOS, Linux)
/// by opening the system browser for authorization and running a local HTTP server
/// to receive the callback. Supports both public clients (no client_id) and
/// confidential clients with PKCE (RFC 7636) for security.
/// 
/// Note: This implementation is designed for desktop platforms. Mobile platforms
/// should use a different OAuth implementation due to differences in how localhost
/// callbacks work on mobile devices.
class WebOAuthHandler {
  static const String _chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
  static final Random _rng = Random();
  static final Logger _logger = Logger('WebOAuthHandler');

  /// Check if current platform is supported (desktop only)
  static bool _isSupportedPlatform() {
    return Platform.isWindows || Platform.isMacOS || Platform.isLinux;
  }

  /// Generates a random string for PKCE code verifier
  static String _generateRandomString(int length) {
    return String.fromCharCodes(
      Iterable.generate(length, (_) => _chars.codeUnitAt(_rng.nextInt(_chars.length))),
    );
  }

  /// Generates PKCE code challenge from verifier
  static String _generateCodeChallenge(String codeVerifier) {
    final bytes = utf8.encode(codeVerifier);
    final digest = sha256.convert(bytes);
    return base64Url.encode(digest.bytes).replaceAll('=', '');
  }

  /// Starts OAuth flow with Authorization Code + PKCE
  static Future<Map<String, dynamic>> startOAuthFlow({
    required String authorizationUrl,
    String? clientId,
    required String redirectUri,
    required String scope,
    String? state,
  }) async {
    if (!_isSupportedPlatform()) {
      throw UnsupportedError('OAuth is not yet supported on mobile platforms');
    }

    try {
      _logger.info('Starting desktop OAuth flow');
      _logger.info('  authorizationUrl: $authorizationUrl');
      _logger.info('  clientId: $clientId');
      _logger.info('  redirectUri: $redirectUri');
      _logger.info('  scope: $scope');

      // Generate PKCE parameters
      final codeVerifier = _generateRandomString(128);
      final codeChallenge = _generateCodeChallenge(codeVerifier);
      final stateParam = state ?? _generateRandomString(32);

      // Parse redirect URI to get port for local server
      final redirectUriParsed = Uri.parse(redirectUri);
      final port = redirectUriParsed.port;

      // Start local HTTP server to receive callback
      final callbackServer = await _CallbackServer.start(port, stateParam);
      
      try {
        // Build authorization URL
        final authUri = Uri.parse(authorizationUrl).replace(queryParameters: {
          'response_type': 'code',
          'redirect_uri': redirectUri,
          'scope': scope,
          'state': stateParam,
          'code_challenge': codeChallenge,
          'code_challenge_method': 'S256',
          if (clientId != null && clientId.isNotEmpty) 'client_id': clientId,
        });

        _logger.info('Opening browser for authorization: $authUri');

        // Open system browser for authorization
        final launched = await launchUrl(
          authUri,
          mode: LaunchMode.externalApplication,
        );

        if (!launched) {
          throw Exception('Failed to open browser for OAuth authorization');
        }

        // Wait for callback
        _logger.info('Waiting for OAuth callback...');
        final result = await callbackServer.waitForCallback();
        
        if (result['error'] != null) {
          throw Exception('OAuth error: ${result['error']} - ${result['error_description'] ?? ''}');
        }

        final code = result['code'];
        if (code == null) {
          throw Exception('Authorization code not received');
        }

        return {
          'code': code,
          'code_verifier': codeVerifier,
          'state': result['state'],
        };
      } finally {
        await callbackServer.close();
      }
    } catch (e) {
      _logger.severe('OAuth flow failed: $e');
      rethrow;
    }
  }

  /// Exchanges authorization code for access token
  static Future<Map<String, dynamic>> exchangeCodeForToken({
    required String tokenUrl,
    String? clientId,
    String? clientSecret,
    required String code,
    required String codeVerifier,
    required String redirectUri,
  }) async {
    if (!_isSupportedPlatform()) {
      throw UnsupportedError('OAuth is not yet supported on mobile platforms');
    }

    try {
      final headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      };

      final body = <String, String>{
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirectUri,
        'code_verifier': codeVerifier,
      };

      // Only include client_id if it's provided and not the default fallback
      if (clientId != null && clientId.isNotEmpty && clientId != 'mcp-client') {
        body['client_id'] = clientId;
      }

      if (clientSecret != null && clientSecret.isNotEmpty) {
        body['client_secret'] = clientSecret;
      }

      _logger.info('Exchanging code for token at: $tokenUrl');

      final response = await http.post(
        Uri.parse(tokenUrl),
        headers: headers,
        body: body.entries.map((e) => '${e.key}=${Uri.encodeComponent(e.value)}').join('&'),
      );

      if (response.statusCode == 200) {
        final tokenData = json.decode(response.body) as Map<String, dynamic>;
        
        // Calculate token expiry if expires_in is provided
        if (tokenData['expires_in'] != null) {
          final expiresIn = tokenData['expires_in'] as int;
          tokenData['expires_at'] = DateTime.now().add(Duration(seconds: expiresIn)).toIso8601String();
        }

        _logger.info('Token exchange successful');
        return tokenData;
      } else {
        final errorBody = response.body;
        _logger.severe('Token exchange failed: ${response.statusCode} - $errorBody');
        throw Exception('Token exchange failed: ${response.statusCode} - $errorBody');
      }
    } catch (e) {
      _logger.severe('Token exchange error: $e');
      rethrow;
    }
  }

  /// Refreshes an expired access token
  static Future<Map<String, dynamic>> refreshToken({
    required String tokenUrl,
    String? clientId,
    String? clientSecret,
    required String refreshToken,
  }) async {
    if (!_isSupportedPlatform()) {
      throw UnsupportedError('OAuth is not yet supported on mobile platforms');
    }

    try {
      final headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      };

      final body = <String, String>{
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
      };

      // Only include client_id if provided
      if (clientId != null && clientId.isNotEmpty) {
        body['client_id'] = clientId;
      }

      if (clientSecret != null && clientSecret.isNotEmpty) {
        body['client_secret'] = clientSecret;
      }

      _logger.info('Refreshing token at: $tokenUrl');

      final response = await http.post(
        Uri.parse(tokenUrl),
        headers: headers,
        body: body.entries.map((e) => '${e.key}=${Uri.encodeComponent(e.value)}').join('&'),
      );

      if (response.statusCode == 200) {
        final tokenData = json.decode(response.body) as Map<String, dynamic>;
        
        // Calculate token expiry if expires_in is provided
        if (tokenData['expires_in'] != null) {
          final expiresIn = tokenData['expires_in'] as int;
          tokenData['expires_at'] = DateTime.now().add(Duration(seconds: expiresIn)).toIso8601String();
        }

        _logger.info('Token refresh successful');
        return tokenData;
      } else {
        final errorBody = response.body;
        _logger.severe('Token refresh failed: ${response.statusCode} - $errorBody');
        throw Exception('Token refresh failed: ${response.statusCode} - $errorBody');
      }
    } catch (e) {
      _logger.severe('Token refresh error: $e');
      rethrow;
    }
  }
}

/// Local HTTP server to handle OAuth callbacks on desktop platforms
class _CallbackServer {
  final HttpServer _server;
  final String _expectedState;
  final Completer<Map<String, String>> _completer = Completer<Map<String, String>>();

  _CallbackServer._(this._server, this._expectedState) {
    _server.listen(_handleRequest);
  }

  /// Starts a local HTTP server on the specified port
  static Future<_CallbackServer> start(int port, String expectedState) async {
    try {
      // Try to bind to the specified port, fallback to any available port
      HttpServer server;
      try {
        server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
      } catch (e) {
        Logger.root.warning('Failed to bind to port $port, using any available port: $e');
        server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      }
      
      Logger.root.info('OAuth callback server started on http://localhost:${server.port}');
      return _CallbackServer._(server, expectedState);
    } catch (e) {
      Logger.root.severe('Failed to start OAuth callback server: $e');
      rethrow;
    }
  }

  /// Handles incoming HTTP requests
  void _handleRequest(HttpRequest request) async {
    try {
      Logger.root.info('Received OAuth callback: ${request.uri}');

      // Extract parameters from query string
      final params = request.uri.queryParameters;
      final code = params['code'];
      final state = params['state'];
      final error = params['error'];
      final errorDescription = params['error_description'];

      // Prepare response HTML
      String responseHtml;
      if (error != null) {
        responseHtml = _buildErrorHtml(error, errorDescription);
        _completer.completeError(Exception('OAuth error: $error - ${errorDescription ?? ''}'));
      } else if (state != _expectedState) {
        responseHtml = _buildErrorHtml('invalid_state', 'State parameter mismatch');
        _completer.completeError(Exception('Invalid state parameter'));
      } else if (code != null) {
        responseHtml = _buildSuccessHtml();
        _completer.complete({
          'code': code,
          'state': state,
        });
      } else {
        responseHtml = _buildErrorHtml('invalid_request', 'No authorization code received');
        _completer.completeError(Exception('No authorization code received'));
      }

      // Send response
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.html
        ..write(responseHtml);
      await request.response.close();

    } catch (e) {
      Logger.root.severe('Error handling OAuth callback: $e');
      request.response
        ..statusCode = 500
        ..write('Internal server error');
      await request.response.close();
    }
  }

  /// Waits for the OAuth callback to complete
  Future<Map<String, String>> waitForCallback() {
    return _completer.future.timeout(
      const Duration(minutes: 10),
      onTimeout: () {
        throw Exception('OAuth flow timed out');
      },
    );
  }

  /// Closes the callback server
  Future<void> close() async {
    await _server.close();
    Logger.root.info('OAuth callback server closed');
  }

  /// Builds success HTML response
  String _buildSuccessHtml() {
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .success-icon {
            font-size: 48px;
            color: #4CAF50;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Authentication Successful</h1>
        <p>You have successfully authenticated with the OAuth provider.</p>
        <p>You can close this window and return to ChatMCP.</p>
    </div>
    <script>
        // Auto-close window after 3 seconds
        setTimeout(function() {
            window.close();
        }, 3000);
    </script>
</body>
</html>
''';
  }

  /// Builds error HTML response
  String _buildErrorHtml(String error, String? errorDescription) {
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .error-icon {
            font-size: 48px;
            color: #f44336;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin-bottom: 20px;
        }
        .error-details {
            background: #ffebee;
            padding: 15px;
            border-radius: 4px;
            color: #c62828;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>There was a problem authenticating with the OAuth provider.</p>
        <div class="error-details">
            <strong>Error:</strong> $error
            ${errorDescription != null ? '<br><strong>Description:</strong> $errorDescription' : ''}
        </div>
        <p style="margin-top: 20px;">You can close this window and try again.</p>
    </div>
</body>
</html>
''';
  }
}
