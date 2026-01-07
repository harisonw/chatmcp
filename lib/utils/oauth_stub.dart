// Stub for mobile platforms (iOS/Android)
// Desktop platforms (Windows/macOS/Linux) use oauth_io.dart
// Web platform uses oauth_web.dart
class WebOAuthHandler {
  static Future<Map<String, dynamic>> startOAuthFlow({
    required String authorizationUrl,
    String? clientId,
    required String redirectUri,
    required String scope,
    String? state,
  }) async {
    throw UnsupportedError('OAuth is not yet supported on mobile platforms');
  }

  static Future<Map<String, dynamic>> exchangeCodeForToken({
    required String tokenUrl,
    String? clientId,
    String? clientSecret,
    required String code,
    required String codeVerifier,
    required String redirectUri,
  }) async {
    throw UnsupportedError('OAuth is not yet supported on mobile platforms');
  }

  static Future<Map<String, dynamic>> refreshToken({
    required String tokenUrl,
    String? clientId,
    String? clientSecret,
    required String refreshToken,
  }) async {
    throw UnsupportedError('OAuth is not yet supported on mobile platforms');
  }
}
