[![Pub]](https://pub.dartlang.org/packages/dart_cose)

# dart_cose

A package that can be used to decode and validate a COSE that contains
a European Digital Green Certificate (DGC).

## Getting Started

Import the COSE as binary (List<int>) and your keys in a map 
kid => PEM and call the decodeAndVerify function on Cose.
