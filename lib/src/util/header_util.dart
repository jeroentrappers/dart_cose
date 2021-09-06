import 'dart:convert';

import 'dart:typed_data';

class HeaderUtil {
  static const _PARTY_U_NONCE = -22; // ignore: unused_field
  static const _STATID_KEY_ID = -3; // ignore: unused_field
  static const _STATIC_KEY = -2; // ignore: unused_field
  static const _EPHEMERAL_KEY = -1; // ignore: unused_field
  static const _ALG_HEADER = 1;
  static const _CRIT = 2; // ignore: unused_field
  static const _CONTENT_TYPE = 3; // ignore: unused_field
  static const _KID_HEADER = 4;
  static const _IV = 5; // ignore: unused_field
  static const _PARTIAL_IV = 6; // ignore: unused_field
  static const _COUNTER_SIGNATURE = 7; // ignore: unused_field

  HeaderUtil._();

  static String parseKid(
      Map<dynamic, dynamic> header, Map<dynamic, dynamic> unprotectedHeader) {
    final kidKey = _KID_HEADER;
    // fall back to unprotected header if protected is not provided.
    final kidBuffer = header[kidKey] ?? unprotectedHeader[kidKey];
    var kid = Uint8List.view(kidBuffer.buffer, 0, kidBuffer.length);
    // Allow more than 8 bytes for UK. Take the entire value and evaluate.
    //if (kid.length > 8) {
    //  kid = kid.sublist(0, 8);
    //}
    return base64.encode(kid);
  }

  static int parseAlg(
      Map<dynamic, dynamic> header, Map<dynamic, dynamic> unprotectedHeader) {
    final algKey = _ALG_HEADER;
    return header[algKey] ?? unprotectedHeader[algKey];
  }
}
