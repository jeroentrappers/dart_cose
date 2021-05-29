[![Pub](https://img.shields.io/pub/v/dart_cose.svg)](https://pub.dartlang.org/packages/dart_cose)
[![Build status](https://travis-ci.com/jeroentrappers/dart_cose.svg?branch=main)](https://travis-ci.com/github/jeroentrappers/dart_cose)

# dart_cose

A package that can be used to decode and validate a COSE that contains
a European Digital Green Certificate (DGC).

## Getting Started

Import the COSE as binary (List<int>) and your keys in a map 
kid => PEM and call the decodeAndVerify function on Cose.

Example:

```dart
    final result = Cose.decodeAndVerify(
        coseIntList,
        {
          'kid': '''pem'''
        },
    );
    print(result.errorCode);
    print(result.verified);
    print(result.payload);
```
