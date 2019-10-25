# Change Log

## [4.2.0] - 02-03-2018
- Added SHA-256 and SHA-512 support

## [4.1.1] - 10-02-2018
### Fixes
- Fix crash with invalid msg from zlib

### Updates
- License information update

## [4.1.0] - 07-06-2017
### Changes
- Compatible with old compilers
- Changed `byte` to `RipeByte` for compatibility with other typedef

## [4.0.1] - 26-09-2017
### Updates
- Updated headers

## [4.0.0] - 17-08-2017
### Changes
- All errors are throwing runtime exceptions instead of logging

### Updated
- All the compiler warnings are report as error

## [3.3.0] - 27-07-2017
### Added
- Ability to encrypt using specified IV

## [3.2.2] - 22-07-2017
### Changes
- Minor refactor and documentation update

## [3.2.1] - 20-07-2017
### Updates
- Updated documentation
- Changed licence from MIT to Apache-2.0

## [3.2.0] - 10-07-2017
### Added
- Ability to generate private RSA keys using `--secret` param

### Fixed
- Fixed `maxRSABlockSize` and `minRSAKeySize` calculations

## [3.1.0] - 06-07-2017
### Added
- Added support to sign and verify using RSA keypair

## [3.0.0] - 15-05-2017
### Changes
- Changed `prepareData` to accept `string` instead

## [2.4.1] - 26-03-2017
### Added
- Support `--out` in zlib for writing to the file (CLI Tool).

## [2.4.0] - 25-03-2017
### Added
- Added `minRSAKeySize` helper to calculate minimum RSA key size for specified data size
- Added zlib compression and decompression functions

## [2.3.0] - 11-03-2017
### Changes
- Removed length as header and added `\r\n\r\n` delimiter
- Added `PACKET_DELIMITER` and `PACKET_DELIMITER_SIZE`
- `--clean` now right-trims the input data instead of removing `0-<first delimiter>`

### Added
- Added helper `isBase64`

## [2.2.0] - 08-03-2017
### Changes
- Updated help output to include option table
- Changed signature for `encryptRSA` and `decryptRSA` to remove length
- Changed `decryptRSA` signature to include `isHex`

### Added
- Added `--raw` option for RSA output

## [2.1.0] - 07-03-2017
### Removed
- Removed `base64Encode(const byte*, std::size_t)`

### Fixed
- Unused warnings for some variables
- Removed unnecessary constructor for `generateRSAKeyPairBase64`

### Changes
- Renamed `normalizeIV` to `normalizeHex`
- Renamed `hexToByte` to `hexToString`
- Improved `FindRipe.cmake` cmake module to search for static and dynamic based on flag `Ripe_USE_STATIC_LIBS`

### Added
- `--hex` option in tool to encode / decode hex strings
- Ability to build ripe as static library

## [2.0.2] - 04-03-2017
### Fixed
- Added compatibility with openssl (issue #2)

## [2.0.1] - 04-03-2017
### Fixed
- Removed dependancy for openssl from cmake

## [2.0.0] - 04-03-2017
### Changed
- Switched to crypto++ (issue #1)
- Merged `RipeHelpers` with `Ripe`
- Major changes to API
- tool; Replaced `--length-included` to `--clean`
- tool; Added `--secret` option
- tool; Added AES key generation using `--aes`

### Added
- api; `Ripe::expectedAESCipherLength`
- api; `Ripe::expectedDataSize`

## [1.1.4] - 01-02-2017
### Changed
- Removed length stuffs from decryptAES

## [1.1.3] - 01-02-2017
### Changed
- Added payload length in prepare()
- Changed decryptAES signature

## [1.1.2] - 13-02-2017
### Fixed
- Fixed versioning

### Added
- Documentation and website (https://amrayn.github.io/ripe)

## [1.1.0] - 10-02-2017
### Changed
- Removed references of OpenSSL from header

### Added
* Added version() for version info

## [1.0.0] - 02-02-2016
### Added
- Initial release
