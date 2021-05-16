# Example

To use the library, you have to provide a COSE as binary data.
Next, it will be decoded and validated against the DGC Spec.

As a result you will receive a CoseResult, which contains
 * a map which contains the payload
 * a bool verified, which indicates that the COSE signature could be verified
 * a CoseErrorCode errorCode, that indicates the type of error

```
// binary representation of the COSE structure
final List<int> cose = ...
// Map containing kid => Base64 encoded DER, or String PEM.
final Map<String, String> keys = ...

var result = Cose.decodeAndVerify(cose, keys);

print(result);

```
