import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as shelf_io;

/// Desktop-based OAuth 2.0 + PKCE handler for MCP servers
/// 
/// Handles OAuth authorization flows in desktop environments using external browser
/// and local HTTP server for callback handling. Supports both public clients (no client_id)
/// and confidential clients with PKCE (RFC 7636) for security.
/// 
/// Note: This implementation does not support concurrent OAuth flows. Only one
/// OAuth flow can be active at a time.
class WebOAuthHandler {
  static const String _chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
  static final Random _rng = Random();
  static HttpServer? _callbackServer;
  static Completer<Map<String, String>>? _callbackCompleter;
  static int? _lastCallbackPort;
  
  /// Default fallback client ID used by some implementations
  static const String _fallbackClientId = 'mcp-client';

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

  /// Starts a local HTTP server to handle OAuth callback
  static Future<int> _startCallbackServer(String expectedState) async {
    // Find an available port
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _callbackServer = server;
    final port = server.port;
    _lastCallbackPort = port;
    
    Logger.root.info('OAuth callback server started on port $port');
    
    // Create a shelf handler
    final handler = shelf.Pipeline()
        .addMiddleware(shelf.logRequests())
        .addHandler((shelf.Request request) async {
      
      // Only handle GET requests to the root path
      if (request.method != 'GET' || request.url.path != '') {
        return shelf.Response.notFound('Not Found');
      }
      
      final params = request.url.queryParameters;
      Logger.root.info('Received OAuth callback with params: $params');
      
      // Check for error
      if (params.containsKey('error')) {
        final error = params['error'];
        final errorDescription = params['error_description'] ?? '';
        Logger.root.severe('OAuth error: $error - $errorDescription');
        
        if (_callbackCompleter != null && !_callbackCompleter!.isCompleted) {
          _callbackCompleter!.completeError(
            Exception('OAuth error: $error - $errorDescription')
          );
        }
        
        return shelf.Response.ok(
          '''
          <html>
            <head><title>Authentication Error</title></head>
            <body>
              <h1>Authentication Error</h1>
              <p>Error: $error</p>
              <p>$errorDescription</p>
              <p>You can close this window.</p>
            </body>
          </html>
          ''',
          headers: {'Content-Type': 'text/html'},
        );
      }
      
      // Verify state parameter
      final state = params['state'];
      if (state != expectedState) {
        Logger.root.severe('State mismatch - expected: $expectedState, got: $state');
        
        if (_callbackCompleter != null && !_callbackCompleter!.isCompleted) {
          _callbackCompleter!.completeError(
            Exception('Invalid state parameter - possible CSRF attack')
          );
        }
        
        return shelf.Response.ok(
          '''
          <html>
            <head><title>Authentication Error</title></head>
            <body>
              <h1>Authentication Error</h1>
              <p>Invalid state parameter. Please try again.</p>
              <p>You can close this window.</p>
            </body>
          </html>
          ''',
          headers: {'Content-Type': 'text/html'},
        );
      }
      
      // Extract authorization code
      final code = params['code'];
      if (code == null) {
        Logger.root.severe('No authorization code received');
        
        if (_callbackCompleter != null && !_callbackCompleter!.isCompleted) {
          _callbackCompleter!.completeError(
            Exception('No authorization code received')
          );
        }
        
        return shelf.Response.ok(
          '''
          <html>
            <head><title>Authentication Error</title></head>
            <body>
              <h1>Authentication Error</h1>
              <p>No authorization code received.</p>
              <p>You can close this window.</p>
            </body>
          </html>
          ''',
          headers: {'Content-Type': 'text/html'},
        );
      }
      
      // Success - complete the callback
      Logger.root.info('Authorization code received successfully');
      
      if (_callbackCompleter != null && !_callbackCompleter!.isCompleted) {
        _callbackCompleter!.complete({
          'code': code,
          'state': state,
        });
      }
      
      return shelf.Response.ok(
        '''
        <html>
          <head><title>Authentication Successful</title></head>
          <body>
            <h1>Authentication Successful!</h1>
            <p>You have been successfully authenticated.</p>
            <p>You can close this window and return to the application.</p>
            <script>
              // Auto-close after 3 seconds
              setTimeout(function() {
                window.close();
              }, 3000);
            </script>
          </body>
        </html>
        ''',
        headers: {'Content-Type': 'text/html'},
      );
    });
    
    // Serve requests
    shelf_io.serveRequests(server, handler);
    
    return port;
  }

  /// Stops the callback server
  static Future<void> _stopCallbackServer() async {
    if (_callbackServer != null) {
      await _callbackServer!.close(force: true);
      _callbackServer = null;
      Logger.root.info('OAuth callback server stopped');
    }
  }

  /// Starts OAuth flow with Authorization Code + PKCE
  static Future<Map<String, dynamic>> startOAuthFlow({
    required String authorizationUrl,
    String? clientId,
    required String redirectUri,
    required String scope,
    String? state,
  }) async {
    // Ensure no other OAuth flow is in progress
    if (_callbackServer != null) {
      throw Exception('Another OAuth flow is already in progress. Please wait for it to complete.');
    }
    
    try {
      // Debug log the parameters
      Logger.root.info('OAuth Parameters:');
      Logger.root.info('  authorizationUrl: $authorizationUrl');
      Logger.root.info('  clientId: $clientId');
      Logger.root.info('  redirectUri: $redirectUri');
      Logger.root.info('  scope: $scope');
      
      // Generate PKCE parameters
      final codeVerifier = _generateRandomString(128);
      final codeChallenge = _generateCodeChallenge(codeVerifier);
      final stateParam = state ?? _generateRandomString(32);

      // Start local callback server
      final callbackPort = await _startCallbackServer(stateParam);
      final localRedirectUri = 'http://localhost:$callbackPort';
      
      Logger.root.info('Using local redirect URI: $localRedirectUri');

      // Build authorization URL
      final authUri = Uri.parse(authorizationUrl).replace(queryParameters: {
        'response_type': 'code',
        'redirect_uri': localRedirectUri,
        'scope': scope,
        'state': stateParam,
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
        // Only include client_id if provided (some servers support public clients)
        if (clientId != null && clientId.isNotEmpty) 'client_id': clientId,
      });

      Logger.root.info('Starting OAuth flow with URL: $authUri');

      // Open browser for authorization
      final url = Uri.parse(authUri.toString());
      if (await canLaunchUrl(url)) {
        final launched = await launchUrl(
          url,
          mode: LaunchMode.externalApplication,
        );
        
        if (!launched) {
          throw Exception('Failed to launch browser for OAuth authorization');
        }
      } else {
        throw Exception('Cannot launch URL: $authUri');
      }

      // Wait for callback
      _callbackCompleter = Completer<Map<String, String>>();
      
      try {
        final result = await _callbackCompleter!.future.timeout(
          const Duration(minutes: 10),
          onTimeout: () {
            throw Exception('OAuth flow timed out - user did not complete authorization');
          },
        );
        
        // Store the port before stopping the server
        final callbackPort = _lastCallbackPort;
        if (callbackPort == null) {
          throw Exception('Failed to track callback server port');
        }
        
        await _stopCallbackServer();
        
        return {
          'code': result['code']!,
          'code_verifier': codeVerifier,
          'state': result['state']!,
          'redirect_uri': 'http://localhost:$callbackPort', // Include actual redirect URI used
        };
      } catch (e) {
        // Make sure to stop the server on error
        await _stopCallbackServer();
        rethrow;
      }
    } catch (e) {
      Logger.root.severe('OAuth flow failed: $e');
      await _stopCallbackServer();
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
    try {
      final headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      };

      final body = <String, String>{
        'grant_type': 'authorization_code',
        'code': code,
        'code_verifier': codeVerifier,
        'redirect_uri': redirectUri, // Use the redirect_uri from the flow result
      };

      // Only include client_id if it's provided and meaningful
      // Some OAuth servers (like Notion MCP) work with public clients (no client_id)
      // We exclude the fallback client ID as it's used as a placeholder by some implementations
      // and should not be sent to the OAuth server
      if (clientId != null && clientId.isNotEmpty && clientId != _fallbackClientId) {
        body['client_id'] = clientId;
      }

      if (clientSecret != null && clientSecret.isNotEmpty) {
        body['client_secret'] = clientSecret;
      }

      Logger.root.info('Exchanging code for token at: $tokenUrl');

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

        Logger.root.info('Token exchange successful');
        return tokenData;
      } else {
        final errorBody = response.body;
        Logger.root.severe('Token exchange failed: ${response.statusCode} - $errorBody');
        throw Exception('Token exchange failed: ${response.statusCode} - $errorBody');
      }
    } catch (e) {
      Logger.root.severe('Token exchange error: $e');
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

      Logger.root.info('Refreshing token at: $tokenUrl');

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

        Logger.root.info('Token refresh successful');
        return tokenData;
      } else {
        final errorBody = response.body;
        Logger.root.severe('Token refresh failed: ${response.statusCode} - $errorBody');
        throw Exception('Token refresh failed: ${response.statusCode} - $errorBody');
      }
    } catch (e) {
      Logger.root.severe('Token refresh error: $e');
      rethrow;
    }
  }
}
