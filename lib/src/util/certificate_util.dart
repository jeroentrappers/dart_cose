import 'dart:convert';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:x509b/x509.dart';

const _begin_cert = '-----BEGIN CERTIFICATE-----';
const _end_cert = '-----END CERTIFICATE-----';

class CertificateUtil {
  CertificateUtil._();

  static X509Certificate getX509Certificate(String pem) {
    var cert = pem.trim();

    if (cert.startsWith(_begin_cert)) {
      // we expect there to be only 1 cert in the pem, so we take the first.
      return parsePem(pem).first as X509Certificate;
    } else {
      return X509Certificate.fromAsn1(
          ASN1Sequence.fromBytes(base64Decode(pem)));
    }
  }

  static String extractKid(String pem) {
    var cert = pem.trim();

    if (cert.startsWith(_begin_cert) && cert.endsWith(_end_cert)) {
      cert = cert.replaceFirst(_begin_cert, "");
      cert = cert.replaceFirst(_end_cert, "");
      cert = cert.replaceAll("\n", "");
      cert = cert.replaceAll(" ", "");
    }

    //The kid is defined as the first 8 bytes of the SHA256 hash of the certificate.
    final der = base64Decode(cert);
    return base64Encode(sha256.convert(der).bytes.sublist(0, 8));
  }
}
