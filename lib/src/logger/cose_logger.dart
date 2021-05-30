class CoseLogger {
  static var _isEnabled = false;

  const CoseLogger._();

  static void setLoggingEnabled({required bool enabled}) {
    _isEnabled = enabled;
  }

  static void print(dynamic value) {
    if (_isEnabled) print(value);
  }

  static void printError(dynamic value) {
    print(value);
  }
}
