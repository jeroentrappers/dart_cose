// Copyright (c) 2021, Jeroen trappers. All rights reserved. Use of this source
// code is governed by the license that can be found in the LICENSE file

import 'dart:typed_data';
import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:dart_cose/dart_cose.dart';
import 'package:dart_cose/src/logger/cose_logger.dart';
import 'package:dart_cose/src/util/certificate_util.dart';
import 'package:dart_cose/src/util/header_util.dart';
import 'package:x509b/x509.dart'; // TODO replace by x509 when upstream fixes are merged
import 'package:ninja/ninja.dart' as ninja;
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';

class Cose {
  static const _CBOR_DATA_LENGTH = 4;
  static const _CBOR_DATA_PROTECTED_HEADER_INDEX = 0;
  static const _CBOR_DATA_UNPROTECTED_HEADER_INDEX = 1;
  static const _CBOR_DATA_PAYLOAD_BYTES_INDEX = 2;
  static const _CBOR_DATA_SIGNER_INDEX = 3;

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

    if (data.isEmpty) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.cbor_decoding_error);
    }

    // take the first element
    final element = data.first;

    // check if it is of type List
    if (!(element is List)) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.unsupported_format);
    }

    List items = element;
    // check if it has exactly 4 items
    if (items.length != _CBOR_DATA_LENGTH) {
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.invalid_format);
    }

    // extract the useful information.
    final protectedHeader = items[_CBOR_DATA_PROTECTED_HEADER_INDEX];
    final unprotectedHeader = items[_CBOR_DATA_UNPROTECTED_HEADER_INDEX];
    final payloadBytes = items[_CBOR_DATA_PAYLOAD_BYTES_INDEX];
    final signers = items[_CBOR_DATA_SIGNER_INDEX];

    // parse headers.
    final headers = Cbor();
    headers.decodeFromBuffer(protectedHeader);
    var headerList = headers.getDecodedData();
    var header = <dynamic, dynamic>{};
    if (headerList != null) {
      if (!(headerList is List)) {
        return CoseResult(
            payload: {},
            verified: false,
            errorCode: CoseErrorCode.unsupported_header_format);
      }

      if (headerList.isEmpty) {
        return CoseResult(
            payload: {},
            verified: false,
            errorCode: CoseErrorCode.cbor_decoding_error);
      }
      header = headerList.first;
    }

    final bKid = HeaderUtil.parseKid(header, unprotectedHeader);
    final a = HeaderUtil.parseAlg(header, unprotectedHeader);

    CoseLogger.print("kid: $bKid");
    CoseLogger.print("alg: $a");

    // parse the payload
    var payloadCbor = Cbor();
    payloadCbor.decodeFromBuffer(payloadBytes);
    CoseLogger.print(payloadCbor.decodedPrettyPrint());

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
      CoseLogger.printError(e);
      return CoseResult(
          payload: {},
          verified: false,
          errorCode: CoseErrorCode.payload_format_error);
    }
    if (!certs.containsKey(bKid)) {
      return CoseResult(
          payload: payload,
          verified: false,
          errorCode: CoseErrorCode.key_not_found);
    }

    final pem = certs[bKid]!;
    final x509cert = CertificateUtil.getX509Certificate(pem);
    final certKid = extractKid(pem);
    if (certKid != bKid) {
      return CoseResult(
          payload: payload,
          verified: false,
          errorCode: CoseErrorCode.kid_mismatch);
    }

    final sigStructure = Cbor();
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

    final publicKey = x509cert.publicKey;

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
        CoseLogger.print(verified);
      } else if (-35 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.rsa.sha384);
        ninja.RsaVerifier ninv =
            ninja.RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha384);
        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        var verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());
        CoseLogger.print(verified);
      } else if (-36 == a) {
        verifier = publicKey.createVerifier(algorithms.signing.rsa.sha512);

        ninja.RsaVerifier ninv =
            ninja.RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha512);
        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        var verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());
        CoseLogger.print(verified);
      } else if (-37 == a) {
        ninja.RsaSsaPssVerifier ninv = ninja.RsaSsaPssVerifier(
            hasher: sha256, mgf: Mgf1(hasher: sha256), saltLength: 32);

        var npk = ninja.RSAPublicKey(publicKey.modulus, publicKey.exponent);
        verified = ninv.verify(
            npk,
            Uint8List.view(signers.buffer, 0, signers.length),
            sigStructureBytes.buffer.asUint8List());
        CoseLogger.print(verified);
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

  static String extractKid(String pem) => CertificateUtil.extractKid(pem);
}
