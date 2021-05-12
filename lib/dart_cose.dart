library dart_cose;

import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'package:cbor/cbor.dart';
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

const AlgFromTags = {
  -7: {'sign': 'ES256', 'digest': 'SHA-256'},
  -35: {'sign': 'ES384', 'digest': 'SHA-384'},
  -36: {'sign': 'ES512', 'digest': 'SHA-512'}
};

const AlgToTags = {
  'ECDH-SS-512': -28,
  'ECDH-SS': -27,
  'ECDH-ES-512': -26,
  'ECDH-ES': -25,
  'ES256': -7,
  'direct': -6,
  'A128GCM': 1,
  'A192GCM': 2,
  'A256GCM': 3,
  'SHA-256_64': 4,
  'SHA-256-64': 4,
  'HS256/64': 4,
  'SHA-256': 5,
  'HS256': 5,
  'SHA-384': 6,
  'HS384': 6,
  'SHA-512': 7,
  'HS512': 7,
  'AES-CCM-16-64-128': 10,
  'AES-CCM-16-128/64': 10,
  'AES-CCM-16-64-256': 11,
  'AES-CCM-16-256/64': 11,
  'AES-CCM-64-64-128': 12,
  'AES-CCM-64-128/64': 12,
  'AES-CCM-64-64-256': 13,
  'AES-CCM-64-256/64': 13,
  'AES-MAC-128/64': 14,
  'AES-MAC-256/64': 15,
  'AES-MAC-128/128': 25,
  'AES-MAC-256/128': 26,
  'AES-CCM-16-128-128': 30,
  'AES-CCM-16-128/128': 30,
  'AES-CCM-16-128-256': 31,
  'AES-CCM-16-256/128': 31,
  'AES-CCM-64-128-128': 32,
  'AES-CCM-64-128/128': 32,
  'AES-CCM-64-128-256': 33,
  'AES-CCM-64-256/128': 33
};

enum CoseErrorCode {
  none,
  cbor_decoding_error,
  unsupported_format,
  invalid_format,
  unsupported_header_format,
  invalid_header_format,
  payload_format_error,
  key_not_found
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
    var a = header[HeaderParameters['alg']];
    var alg = AlgFromTags[a];
    //print("kid: ${base64.encode(kid)}");
    //print("alg: $alg");

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
    if (!certs.containsKey(base64.encode(kid))) {
      return CoseResult(
          payload: {}, verified: false, errorCode: CoseErrorCode.key_not_found);
    }

    String cert = certs[base64.encode(kid)];
    cert = cert.trim();

    // add pem header and footer if missing.

    if (!(cert.startsWith(begin_cert) && cert.endsWith(end_cert))) {
      cert = begin_cert + '\n' + cert + '\n' + end_cert;
    }

    // we expect there to be only 1 cert in the pem, so we take the first.
    var x509cert = parsePem(cert).first as X509Certificate;

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

    var verifier = publicKey.createVerifier(algorithms.signing.ecdsa.sha256);

    var verified = verifier.verify(sigStructureBytes.buffer.asUint8List(),
        Signature(Uint8List.view(signers.buffer, 0, signers.length)));

    return CoseResult(
        payload: payload, verified: verified, errorCode: CoseErrorCode.none);
  }
}
