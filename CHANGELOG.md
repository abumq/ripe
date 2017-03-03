# Change Log

## [Unreleased]

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
- Documentation and website (https://muflihun.github.io/ripe)

## [1.1.0] - 10-02-2017
### Changed
- Removed references of OpenSSL from header

### Added
* Added version() for version info

## [1.0.0] - 02-02-2016
### Added
- Initial release
