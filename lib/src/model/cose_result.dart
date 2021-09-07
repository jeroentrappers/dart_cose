import 'package:dart_cose/dart_cose.dart';
import 'package:x509b/x509.dart';

class CoseResult {
  final Map payload;
  final bool verified;
  final CoseErrorCode errorCode;
  final String? coseKid; //the kid found inside the COSE header
  final X509Certificate? certificate;
  final PublicKey? publicKey;

  CoseResult(
      {required this.payload,
      required this.verified,
      required this.errorCode,
      required this.coseKid,
      required this.certificate,
      required this.publicKey});

  factory CoseResult.withErrorCode(CoseErrorCode errorCode) {
    return new CoseResult(
        payload: {},
        verified: false,
        errorCode: errorCode,
        coseKid: null,
        certificate: null,
        publicKey: null);
  }

  factory CoseResult.withErrorCodeAndKid(
      CoseErrorCode errorCode, String coseKid) {
    return new CoseResult(
        payload: {},
        verified: false,
        errorCode: errorCode,
        coseKid: coseKid,
        certificate: null,
        publicKey: null);
  }
}
