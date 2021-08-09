import 'dart:io';
import 'dart:core';
import 'package:dart_base45/dart_base45.dart';
import 'package:dart_cose/dart_cose.dart';
import 'package:test/test.dart';

List<int> unChain(String input) {
  // trim HC1
  // Compressed COSE (Base45) (548 chars):
  final trimmedQrString = input.substring(input.indexOf(":") + 1);

  // Base45 decode
  // COSE (Hex) (712 chars):
  final compressedCose = Base45.decode(trimmedQrString);

  // unzip
  // Cose
  ZLibCodec zlib = new ZLibCodec();
  final List<int> cose = zlib.decode(compressedCose);
  return cose;
}

void main() {
  test('validate example QR string', () async {
    var stopwatch = Stopwatch()..start();
    var result = Cose.decodeAndVerify(
        unChain(
            '''HC1:NCF3TDJ%B6FLSTSTYOEKDNXP4H5UV0CXH9M9ESIM NHXK.7TKZ65B9B+PLLC5VC9:BXCNUKMUB4WXKYKMXEE1JAA/C5/DEEA+ZAREDHNHZFC3IKKOL0PK\$2MXGGM+G\$C9EOJI1MNPL+JNIMH7I99QM/FJVCI0DJ WJ/Q6395J4I-B5ET42HPPEPHCRSV8OEQAC5ADNA2P 96PTMKP8DK4LC6DQ4ZIOXHM4FA.KMQP4L7O/VMGF6:/6N9R%EPXCROGO CODFLXQ6Z6NC8P\$WA3AA9EPBDSM+Q8H4O670C57Q4UYQD*O%+Q.SQBDOBKLP64-HQ/HQ+DR-DP71AAKPCPP0%M\$76NV6FJB 1JI7JSTNB95526NL7.KMM473X73ZPMIU1RKA+QIUSQ*N8%MKMI72EWBPHJSC.UPLI906\$8R-3FW8O84B1-ST*QGTA4W7.Y7U01.BUV2U:T2J V5XJ623XXJJPSJ H823I3W..2O56RAIR8L3:EPOSP6KHAO506%.NUKKL7VAAOL26IUR+ZPCR7P 5JBF6RL6AL3:Q:.CI00E6TS3'''),
        {
          'uE7ViYTSegg=':
              '''MIICyzCCAnGgAwIBAgIBATAKBggqhkjOPQQDAjCBqTELMAkGA1UEBhMCREsxKTAnBgNVBAoMIFRoZSBEYW5pc2ggSGVhbHRoIERhdGEgQXV0aG9yaXR5MSkwJwYDVQQLDCBUaGUgRGFuaXNoIEhlYWx0aCBEYXRhIEF1dGhvcml0eTEcMBoGA1UEAwwTVEVTVF9DU0NBX0RHQ19ES18wMTEmMCQGCSqGSIb3DQEJARYXa29udGFrdEBzdW5kaGVkc2RhdGEuZGswHhcNMjEwNTA2MDcxMzI1WhcNMjMwNTA3MDcxMzI1WjCBqDELMAkGA1UEBhMCREsxKTAnBgNVBAoMIFRoZSBEYW5pc2ggSGVhbHRoIERhdGEgQXV0aG9yaXR5MSkwJwYDVQQLDCBUaGUgRGFuaXNoIEhlYWx0aCBEYXRhIEF1dGhvcml0eTEbMBkGA1UEAwwSVEVTVF9EU0NfREdDX0RLXzAxMSYwJAYJKoZIhvcNAQkBFhdrb250YWt0QHN1bmRoZWRzZGF0YS5kazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL0JDUKq2pxjU5RxY1l8bdGpTNRJtAcpdCt+NeCvi4eEhTPz7KIddqBqG4TbylBMqTDYCHrsTxOP4iBRrQE3pyWjgYgwgYUwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBQi6XXC6dQ17M3qyUDZMQPB7ecD7zAfBgNVHSMEGDAWgBS43XjKHFShS4ohleIhOwzEaOS38DAzBgNVHSUELDAqBgwrBgEEAQCON49lAQEGDCsGAQQBAI43j2UBAgYMKwYBBAEAjjePZQEDMAoGCCqGSM49BAMCA0gAMEUCIF7fye27ODGr5oHpPmzGAF32/S8v+9YBtaWsCPg3vzNKAiEAxhxPz1lJo7oHZE5HXq71fOi62hoTxQvK08glhlq228s='''
        });
    print("took: " + stopwatch.elapsedMilliseconds.toString());
    print(result.errorCode);
    expect(result.verified, true);
    expect(result.errorCode, CoseErrorCode.none);
  });

  test('validate example QR string for UK', () async {
    var stopwatch = Stopwatch()..start();
    var result = Cose.decodeAndVerify(
        unChain(
            r'HC1:6BFOXNYTSMAHN-HUVQG:M89AP77N$O6E8N+M3XHV5U6R5JEHHTBAVD A13/4X6BMF6.UCOMI6+QBR7BD7LG8CU6O8QGU68ORJSPZHQW1SZSP:*PG+QV*OEHP/ROMHPO/5  QGU65F4TKRN95U/38T9:H9P1J4HGZJK:HGX2MI C+G9BYI970SC9EY8R2KK3M8FFZ.C-3N$29ALG:.C+-CBJC5IAXMFU*GSHGRKMXGG%DBZI9$JAQJKN94J7J43M3Z8.-B97U: KUZNP3F.6O4DRI%K/YN3CR9*O3-S-YNNCLBLEH-BKMHFDJ:2CUDBQEAJJKKKMWC8WYOZM1NLKA8TK6IR$0/KQ4WDEK4*UO5U9/GJ07QJ1R1*595G QF$1WQ-K.XSDHF6$7DTMTL9YZ928NEOAS:9UAR64NL9K32N YAVGSHB06%C05D'),
        {
          r'S2V5MS1zaXQx':
              r'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyzJjCOd6AZI85tOFAtvagr0MUcnM11ces2tHHsjg/TiEUX0M6tfNJloc27xeLbvrphVUDM5RoLtinu5bCQ1ug=='
        });
    print("took: " + stopwatch.elapsedMilliseconds.toString());
    print(result.errorCode);
    expect(result.verified, true);
    expect(result.errorCode, CoseErrorCode.none);
  });
}
