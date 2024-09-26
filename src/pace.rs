
// ICAO 9303-11 table 12 (p. 58-59)
#[repr(u8)]
pub enum StandardizedDomainPrameter {

    // See RFC 5114: Additional Diffie-Hellman Groups for Use with IETF Standards
    MODP_1024_160 = 0x00, // RFC 5114-2.2
    MODP_2048_224 = 0x01, // RFC 5114-2.3
    MODP_2048_256 = 0x02, // RFC 5114-2.4

    // See RFC 5639:Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation
    EC_SECP192R1 = 0x08, // NIST P-192, SECG p192r1, FIPS 186-4
    EC_B

    // 3-7 and 19-31.
    ReservedForFutureUse(u8),
}
