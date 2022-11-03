# Changelog

## Unreleased (2022-11-03)

#### New Features

* merge dev config in one, add utils ([#64](https://github.com/Mcublog/ofd/issues/64))
* debianization, JWT generation
* implement protocol from 19.10.2016
* implement 1101 tag
* complete validation part
* strict validation, part 1
* update JSON schema
* update protocol
* schema for close shift
* further scheme improvements
* improve scheme on items
* JSON schema for receipt
* use JSON schema for documents
* proper tracing
* crypto module can now be configured
* temporary suppress protocol check for new KKTs
* do not ignore cardinality
* multiple changes
* implement KGB cipher
* update YT schema
* update protocol to ATOL-3
* further improvements
* append into YT instead of rewrite
* add all possible tags
* add session header packer
* implemented responding
* working version
* initial commit
#### Fixes

* add parents to tags, bump 0.24.4
* allow non-unique correction code, bump 0.24.3
* remove user from required in openShift. bump
* protocol fix ([#12](https://github.com/Mcublog/ofd/issues/12))
* fixed correction receipt types in schema
* fix schemas
* use proper taxation_type tag for reports
* protocol compatibility with v2
* add missing protocol field
* add more protocol tags
#### Refactorings

* tests, add CI
* fix validators to match new protocol
* types
* new data
* dead code elimination
* protocol switch
* fiscalSign is a number now
* accept both 1 and 2 A-protocol
* proper cardinality handling
* make some methods static
* early corrupted protocol detection
* server decomposition, add unit tests
* adapt with python 3
* decomposition
* drop another magic constant
* calculate CRC for frame header
* drop magic constant
* frame headers now has its own class
* add stub for CRC
* add more tests
#### Docs

* fix python in examples, some wording
