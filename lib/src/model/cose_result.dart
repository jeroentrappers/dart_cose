import 'package:dart_cose/dart_cose.dart';
import 'package:x509b/x509.dart';

class CoseResult {
  final Map payload;
  final bool verified;
  final CoseErrorCode errorCode;
  final X509Certificate? certificate;
  final PublicKey? publicKey;

  CoseResult(
      {required this.payload,
      required this.verified,
      required this.errorCode,
      required this.certificate,
      required this.publicKey});
}
