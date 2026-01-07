import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

/// Desktop-based OAuth 2.0 + PKCE handler for MCP servers
/// 
/// Handles OAuth authorization flows in desktop environments using system browser
/// and local HTTP server for callback. Supports both public clients (no client_id)
/// and confidential clients with PKCE (RFC 7636) for security.
class WebOAuthHandler {
  static const String _chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
  static final Random _rng = Random();
  
  // Default fallback client ID for public clients
  static const String _defaultClientId = 'mcp-client';
  
  // OAuth flow timeout duration
  static const Duration _oauthTimeout = Duration(minutes: 10);

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

      // Start local HTTP server for callback
      final server = await _startCallbackServer();
      final port = server.port;
      final localRedirectUri = 'http://localhost:$port/callback';
      
      Logger.root.info('Local callback server started on port: $port');
      Logger.root.info('Using local redirect URI: $localRedirectUri (ignoring provided redirectUri for desktop)');

      // Build authorization URL - use local redirect URI for desktop
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

      // Open system browser for authorization
      final uri = Uri.parse(authUri.toString());
      if (!await launchUrl(uri, mode: LaunchMode.externalApplication)) {
        await server.close();
        throw Exception('Could not launch browser for OAuth authorization');
      }

      try {
        // Wait for the callback
        final result = await _waitForCallback(server, stateParam);
        
        // Extract authorization code from callback
        final code = result['code'];
        if (code == null) {
          throw Exception('Authorization code not received');
        }

        return {
          'code': code,
          'code_verifier': codeVerifier,
          'state': result['state'],
          'redirect_uri': localRedirectUri, // Return the actual redirect URI used
        };
      } catch (e) {
        await server.close();
        rethrow;
      }
    } catch (e) {
      Logger.root.severe('OAuth flow failed: $e');
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
        'redirect_uri': redirectUri,
        'code_verifier': codeVerifier,
      };

      // Only include client_id if it's provided and not the default fallback
      // Some OAuth servers (like Notion MCP) work with public clients (no client_id)
      if (clientId != null && clientId.isNotEmpty && clientId != _defaultClientId) {
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

  /// Starts local HTTP server for OAuth callback
  static Future<HttpServer> _startCallbackServer() async {
    // Try to bind to IPv4 loopback first, fall back to IPv6 if that fails
    try {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      Logger.root.info('Callback server started on IPv4 port: ${server.port}');
      return server;
    } catch (e) {
      Logger.root.warning('Failed to bind to IPv4 loopback, trying IPv6: $e');
      final server = await HttpServer.bind(InternetAddress.loopbackIPv6, 0);
      Logger.root.info('Callback server started on IPv6 port: ${server.port}');
      return server;
    }
  }

  /// Waits for OAuth callback on local HTTP server
  static Future<Map<String, String>> _waitForCallback(
    HttpServer server,
    String expectedState,
  ) async {
    final completer = Completer<Map<String, String>>();
    
    Logger.root.info('Waiting for OAuth callback...');
    Logger.root.info('Expected state: $expectedState');
    
    // Set up request listener
    late StreamSubscription<HttpRequest> subscription;
    
    subscription = server.listen((HttpRequest request) async {
      try {
        Logger.root.info('Received request: ${request.uri}');
        
        // Check if this is the callback path
        if (request.uri.path == '/callback') {
          final params = request.uri.queryParameters;
          
          Logger.root.info('Callback parameters: $params');
          
          // Send response to browser
          request.response.headers.contentType = ContentType.html;
          
          // Check for error
          if (params['error'] != null) {
            final error = params['error'];
            final errorDescription = params['error_description'] ?? '';
            
            Logger.root.severe('OAuth error received: $error - $errorDescription');
            
            request.response.write('''
              <!DOCTYPE html>
              <html>
              <head>
                  <title>Authentication Failed</title>
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
                          max-width: 500px;
                      }
                      h2 { color: #e74c3c; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h2>❌ Authentication Failed</h2>
                      <p>Error: $error</p>
                      <p>$errorDescription</p>
                      <p>You can close this window and return to the application.</p>
                  </div>
              </body>
              </html>
            ''');
            await request.response.close();
            
            subscription.cancel();
            await server.close();
            completer.completeError(Exception('OAuth error: $error - $errorDescription'));
            return;
          }
          
          // Verify state parameter
          if (params['state'] != expectedState) {
            Logger.root.severe('State mismatch - expected: $expectedState, got: ${params['state']}');
            
            request.response.write('''
              <!DOCTYPE html>
              <html>
              <head>
                  <title>Authentication Failed</title>
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
                          max-width: 500px;
                      }
                      h2 { color: #e74c3c; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h2>❌ Authentication Failed</h2>
                      <p>Security validation failed (invalid state parameter)</p>
                      <p>You can close this window and return to the application.</p>
                  </div>
              </body>
              </html>
            ''');
            await request.response.close();
            
            subscription.cancel();
            await server.close();
            completer.completeError(Exception('Invalid state parameter'));
            return;
          }
          
          // Check for authorization code
          final code = params['code'];
          if (code != null) {
            Logger.root.info('Authorization code received successfully');
            
            request.response.write('''
              <!DOCTYPE html>
              <html>
              <head>
                  <title>Authentication Successful</title>
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
                          max-width: 500px;
                      }
                      h2 { color: #27ae60; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h2>✅ Authentication Successful</h2>
                      <p>You have successfully authenticated!</p>
                      <p>You can close this window and return to the application.</p>
                  </div>
              </body>
              </html>
            ''');
            await request.response.close();
            
            subscription.cancel();
            await server.close();
            
            completer.complete({
              'code': code,
              'state': params['state']!,
            });
          } else {
            Logger.root.severe('No authorization code received');
            
            request.response.write('''
              <!DOCTYPE html>
              <html>
              <head>
                  <title>Authentication Failed</title>
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
                          max-width: 500px;
                      }
                      h2 { color: #e74c3c; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h2>❌ Authentication Failed</h2>
                      <p>No authorization code received</p>
                      <p>You can close this window and return to the application.</p>
                  </div>
              </body>
              </html>
            ''');
            await request.response.close();
            
            subscription.cancel();
            await server.close();
            completer.completeError(Exception('Authorization code not received'));
          }
        } else {
          // Not the callback path, send 404
          request.response.statusCode = HttpStatus.notFound;
          await request.response.close();
        }
      } catch (e) {
        Logger.root.severe('Error processing OAuth callback: $e');
        request.response.statusCode = HttpStatus.internalServerError;
        await request.response.close();
        
        if (!completer.isCompleted) {
          subscription.cancel();
          await server.close();
          completer.completeError(e);
        }
      }
    });

    // Set timeout for the callback
    return completer.future.timeout(
      _oauthTimeout,
      onTimeout: () {
        subscription.cancel();
        server.close();
        throw Exception('OAuth flow timed out after ${_oauthTimeout.inMinutes} minutes');
      },
    );
  }
}
