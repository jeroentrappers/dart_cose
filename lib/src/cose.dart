// Copyright (c) 2021, Jeroen trappers. All rights reserved. Use of this source
// code is governed by the license that can be found in the LICENSE file

library dart_cose;

import 'dart:typed_data';
import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:x509b/x509.dart'; // TODO replace by x509 when upstream fixes are merged
import 'package:ninja/ninja.dart' as ninja;
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';

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
  'kid': 4,
  'IV': 5,
  'Partial_IV': 6,
  'counter_signature': 7
};

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

  CoseResult(
      {required this.payload, required this.verified, required this.errorCode});
}

class Cose {
  // input: cose as binary, certs as map kid -> PEM
  static CoseResult decodeAndVerify(List<int> cose, Map<String, String> certs) {
    var inst = Cbor();
    inst.decodeFromList(cose);
    List<dynamic>? data = inst.getDecodedData();

    if (null == data) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.cbor_decoding_error);
    }

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

    List items = element;
    // check if it has exactly 4 items
    if (4 != items.length) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.invalid_format);
    }

    // extract the useful information.
    final protectedHeader = items[0];
    final unprotectedHeader = items[1];
    final payloadBytes = items[2];
    final signers = items[3];

    // parse headers.
    var headers = Cbor();
    headers.decodeFromBuffer(protectedHeader);
    var headerList = headers.getDecodedData();
    var header = {};
    if (headerList != null) {
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
      header = headerList.first;
    }

    final kidKey = HeaderParameters['kid'];
    // fall back to unprotected header if protected is not provided.
    var kidBuffer = header[kidKey] ?? unprotectedHeader[kidKey];
    var kid = Uint8List.view(kidBuffer.buffer, 0, kidBuffer.length);
    if (kid.length > 8) {
      kid = kid.sublist(0, 8);
    }
    final bkid = base64.encode(kid);

    final algKey = HeaderParameters['alg'];
    final a = header[algKey] ?? unprotectedHeader[algKey];

    //print("kid: ${base64.encode(kid)}");
    //print("alg: $a");

    // parse the payload
    var payloadCbor = Cbor();
    payloadCbor.decodeFromBuffer(payloadBytes);
    //print(payloadCbor.decodedPrettyPrint());

    dynamic payload = {};
    try {
      var data = payloadCbor.getDecodedData();
      if (null == data) {
        return CoseResult(
            payload: {},
            verified: false,
            errorCode: CoseErrorCode.payload_format_error);
      }
      payload = data.first;
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

    String derB64 = certs[bkid]!;
    String cert = derB64.trim();

    // add pem header and footer if missing.

    if (!(cert.startsWith(begin_cert) && cert.endsWith(end_cert))) {
      cert = begin_cert + '\n' + cert + '\n' + end_cert;
    } else {
      derB64 = cert.replaceFirst(begin_cert, "");
      derB64 = derB64.replaceFirst(end_cert, "");
      derB64 = derB64.replaceAll("\n", "");
      derB64 = derB64.replaceAll(" ", "");
    }

    // we expect there to be only 1 cert in the pem, so we take the first.
    var x509cert = parsePem(cert).first as X509Certificate;

    //The kid is defined as the first 8 bytes of the SHA256 hash of the certificate.
    var der = base64Decode(derB64);
    var certKid = base64Encode(sha256.convert(der).bytes.sublist(0, 8));

    if (certKid != bkid) {
      return CoseResult(
          payload: payload,
          verified: false,
          errorCode: CoseErrorCode.kid_mismatch);
    }

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
    Verifier? verifier;
    bool verified = false;
    if (publicKey is EcPublicKey) {
      // primary algorithm
      /// ECDSA using P-256 and SHA-256
      if (-7 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.ecdsa.sha256);
      } else if (-35 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.ecdsa.sha384);
      } else if (-36 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.ecdsa.sha512);
      } else {
        return CoseResult(
            payload: payload,
            verified: false,
            errorCode: CoseErrorCode.unsupported_algorithm);
      }
    } else if (publicKey is RsaPublicKey) {
      // secondary algorithm
      /// RSASSA-PKCS1-v1_5 using SHA-256
      if (-7 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.rsa.sha256);
        ninja.RsaVerifier ninv =
            ninja.RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha256);
        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        var verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());
        print(verified);
      } else if (-35 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.rsa.sha384);
        ninja.RsaVerifier ninv =
            ninja.RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha384);
        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        var verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());
        print(verified);
      } else if (-36 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.rsa.sha512);

        ninja.RsaVerifier ninv =
            ninja.RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha512);
        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        var verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());
        print(verified);
      } else if (-37 == a) {
        ninja.RsaSsaPssVerifier ninv = ninja.RsaSsaPssVerifier(
            hasher: sha256, mgf: Mgf1(hasher: sha256), saltLength: 32);

        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());

        print(verified);
      } else {
        return CoseResult(
            payload: payload,
            verified: false,
            errorCode: CoseErrorCode.unsupported_algorithm);
      }
    } else {
      return CoseResult(
          payload: payload,
          verified: false,
          errorCode: CoseErrorCode.unsupported_algorithm);
    }

    if (!verified && verifier != null) {
      verified = verifier.verify(sigStructureBytes.buffer.asUint8List(),
          Signature(Uint8List.view(signers.buffer, 0, signers.length)));
    }

    return CoseResult(
        payload: payload, verified: verified, errorCode: CoseErrorCode.none);
  }
}
