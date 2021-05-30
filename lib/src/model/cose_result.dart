import 'package:dart_cose/dart_cose.dart';

class CoseResult {
  final Map payload;
  final bool verified;
  final CoseErrorCode errorCode;

  CoseResult({
    required this.payload,
    required this.verified,
    required this.errorCode,
  });
}
