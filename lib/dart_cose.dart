library dart_cose;

import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:x509/x509.dart';

const begin_cert = '-----BEGIN CERTIFICATE-----';
const end_cert = '-----END CERTIFICATE-----';

const HeaderParameters = {
  'partyUNonce': -22,
  'static_key_id': -3,
  'static_key': -2,
  'ephemeral_key': -1,
  'alg': 1,
  'crit': 2,
  'content_type': 3,
  'ctyp': 3, // one could question this but it makes testing easier
  'kid': 4,
  'IV': 5,
  'Partial_IV': 6,
  'counter_signature': 7
};

String calcKid(X509Certificate cert) {
  var encoded = cert.toAsn1().encodedBytes;
  var hash = sha256.convert(encoded);
  return base64Encode(hash.bytes);
}

enum CoseErrorCode {
  none,
  cbor_decoding_error,
  unsupported_format,
  invalid_format,
  unsupported_header_format,
  invalid_header_format,
  payload_format_error,
  key_not_found,
  kid_mismatch,
  unsupported_algorithm
}

class CoseResult {
  final Map payload;
  final bool verified;
  final CoseErrorCode errorCode;

  CoseResult({this.payload, this.verified, this.errorCode});
}

/// A Calculator.
class Cose {
  // input: cose as binary, certs as map kid -> PEM
  static CoseResult decodeAndVerify(List<int> cose, Map<String, String> certs) {
    var inst = Cbor();
    inst.decodeFromList(cose);
    List data = inst.getDecodedData();

    if (data.length <= 0) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.cbor_decoding_error);
    }

    // take the first element
    var element = data.first;

    // check if it is of type List
    if (!(element is List)) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.unsupported_format);
    }

    List items = element as List;
    // check if it has exactly 4 items
    if (4 != items.length) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.invalid_format);
    }

    // extract the useful information.
    final protectedHeader = items[0];
    //final unprotectedHeader = items[1];
    final payloadBytes = items[2];
    final signers = items[3];

    // parse headers.
    var headers = Cbor();
    headers.decodeFromBuffer(protectedHeader);
    var headerList = headers.getDecodedData();
    if (!(headerList is List)) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.unsupported_header_format);
    }

    if (headerList.length <= 0) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.cbor_decoding_error);
    }

    var header = headerList.first;

    var kid = header[HeaderParameters['kid']];
    var bkid = base64.encode(kid);
    //var a = header[HeaderParameters['alg']];
    //print("kid: ${base64.encode(kid)}");
    //print("alg: $a");

    // parse the payload
    var payloadCbor = Cbor();
    payloadCbor.decodeFromBuffer(payloadBytes);
    //print(payloadCbor.decodedPrettyPrint());

    dynamic payload = {};
    try {
      payload = payloadCbor.getDecodedData().first;
    } on Exception catch (e) {
      print(e);
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.payload_format_error);
    }
    if (!certs.containsKey(bkid)) {
      return CoseResult(
          payload: payload,
          verified: false,
          errorCode: CoseErrorCode.key_not_found);
    }

    String cert = certs[bkid];
    cert = cert.trim();

    // add pem header and footer if missing.

    if (!(cert.startsWith(begin_cert) && cert.endsWith(end_cert))) {
      cert = begin_cert + '\n' + cert + '\n' + end_cert;
    }

    // we expect there to be only 1 cert in the pem, so we take the first.
    var x509cert = parsePem(cert).first as X509Certificate;

    // var cKid = calcKid(x509cert);
    // // check if kid matches
    // if (cKid != bkid) {
    //   return CoseResult(
    //       payload: {}, verified: false, errorCode: CoseErrorCode.kid_mismatch);
    // }

    var sigStructure = Cbor();
    final sigStructureEncoder = sigStructure.encoder;

    sigStructureEncoder.writeArray([
      'Signature1', // context string
      Uint8List.view(protectedHeader.buffer, 0,
          protectedHeader.length), // protected body (header)
      Uint8List(0),
      Uint8List.view(payloadBytes.buffer, 0, payloadBytes.length)
    ]);

    sigStructure.decodeFromInput();
    final sigStructureBytes = sigStructure.output.getData();

    var publicKey = x509cert.publicKey;

    // -7: {'sign': 'ES256', 'digest': 'SHA-256'},
    Verifier verifier;
    if (publicKey is EcPublicKey) {
      // primary algorithm
      /// ECDSA using P-256 and SHA-256
      verifier = publicKey.createVerifier(algorithms.signing.ecdsa.sha256);
    } else if (publicKey is RsaPublicKey) {
      // secondary algorithm
      /// RSASSA-PKCS1-v1_5 using SHA-256
      verifier = publicKey.createVerifier(algorithms.signing.rsa.sha256);
    } else {
      return CoseResult(
          payload: payload,
          verified: false,
          errorCode: CoseErrorCode.unsupported_algorithm);
    }

    var verified = verifier.verify(sigStructureBytes.buffer.asUint8List(),
        Signature(Uint8List.view(signers.buffer, 0, signers.length)));

    return CoseResult(
        payload: payload, verified: verified, errorCode: CoseErrorCode.none);
  }
}
