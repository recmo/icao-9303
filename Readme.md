# ICAO 9303: Electronic Machine Readable Travel Documents

Implementation of the ICAO 9303 standard for electronic machine readable travel documents (eMRTD) in Rust. This covers the data structure, cryptographic operations, and communication protocols for eMRTDs.

## Status

This is a work in progress. The following features are implemented:

* ASN1 Data structure for eMRTD.
* Basic APDU communication with eMRTDs.
* Cryptographic operations for:
  * Secure Messaging
  * Basic Access Control
  * Chip Authentication
  * Data group hashes
* Proxmark3 USB support for interacting with eMRTDs.

Not implemented yet:
 * MRZ parsing
 * PACE
 * Document signature verification
 * Cetificate chain validation
 * Named parameters for cryptographic operations
 * Chained APDUs and responses

Not planned:
 * Terminal Authentication

## References

* ICAO 9303: Machine Readable Travel Documents.
  <https://www.icao.int/publications/pages/publication.aspx?docnum=9303>

General:

* ISO/IEC 7816-4: Integrated Circuit(s) Cards with Contacts.
* ISO/IEC 14443-3: Proximity Cards.
* ITU-T X.690: ASN.1 encoding rules.

Cryptography:

* RFC 5280
* RFC 5480
* RFC 5114
* RFC 5639
* RFC 5652
* ANSI X9.42: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography.
* ANSI X9.62: Public Key Cryptography for the Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA).
* FIPS 46-3: Data Encryption Standard (DES).
* BSI TR-03105: Advanced Security Mechanisms for Machine Readable Travel Documents.
* BSI TR-03110: Biometrics in Machine Readable Travel Documents.
* BSI TR-03111: Security Mechanisms for Electronic Passports.

CBC mode for block ciphers:

* ISO/IEC 10116-2006. Information technology – Security techniques – Modes of operation
for an n-bit block cipher, 2006.

CMAC mode for block ciphers:

* NIST SP 800-38B: Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication. <https://csrc.nist.gov/pubs/sp/800/38/b/final>

Physical layer:

* ECMA 340: Near Field Communication Interface and Protocol 1 (NFCIP-1)
* ECMA 352: Near Field Communication Interface and Protocol 2 (NFCIP-2)
* ISO/IEC 18000-3: Radio frequency identification for item management — Part 3: Parameters for air interface communications at 13,56 MHz
