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
