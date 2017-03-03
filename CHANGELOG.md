# Change Log

## [Unreleased]
### Changed
- api; Base64 functions using Crypto++
- api; AES encryption and decryption using Crypto++
- api; Changed `Ripe::expectedBase64Length` to take and return `std::size_t`
- api; Renamed `RipeHelpers` => `Ripe` and `Ripe` => `RipeCrypto`
- tool; Replaced `--length-included` to `--clean`
- tool; Added AES key generation using `--aes`
- api; Removed a lot of redundant AES helper methods
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
- Documentation and website (https://muflihun.github.io/ripe)

## [1.1.0] - 10-02-2017
### Changed
- Removed references of OpenSSL from header

### Added
* Added version() for version info

## [1.0.0] - 02-02-2016
### Added
- Initial release
