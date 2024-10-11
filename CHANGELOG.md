# Changelog

## [0.5.0](https://github.com/cccteam/access/compare/v0.4.1...v0.5.0) (2024-10-11)


### ⚠ BREAKING CHANGES

* Update for changes in the UserPermissionCollection type from accesstypes ([#35](https://github.com/cccteam/access/issues/35))

### Features

* Implement support for loading role configuration ([#36](https://github.com/cccteam/access/issues/36)) ([0317a69](https://github.com/cccteam/access/commit/0317a693726e35f8bc77b178d7c68c1803c0226d))


### Bug Fixes

* Disable database creation for Spanner adapter ([#34](https://github.com/cccteam/access/issues/34)) ([1957664](https://github.com/cccteam/access/commit/195766485bb39d2db8e547df39d3b9791b3e46af))
* Reword error message in NewAdapter function on SpannerAdapter to return the correct package ([#32](https://github.com/cccteam/access/issues/32)) ([743a989](https://github.com/cccteam/access/commit/743a9894775338672340881d51216b44127d8c15))


### Code Refactoring

* Update for changes in the UserPermissionCollection type from accesstypes ([#35](https://github.com/cccteam/access/issues/35)) ([3f05aca](https://github.com/cccteam/access/commit/3f05acadacce283279eccad88c1fddca68a56e9a))


### Code Upgrade

* Update go dependencies ([#37](https://github.com/cccteam/access/issues/37)) ([8dd9c59](https://github.com/cccteam/access/commit/8dd9c598272099ee1e7343bfd3fdb992529e7346))

## [0.4.1](https://github.com/cccteam/access/compare/v0.4.0...v0.4.1) (2024-10-08)


### Code Upgrade

* Go dependency updates ([#29](https://github.com/cccteam/access/issues/29)) ([3bc8181](https://github.com/cccteam/access/commit/3bc81819b4d980f5b0d058086d07269809f98487))

## [0.4.0](https://github.com/cccteam/access/compare/v0.3.0...v0.4.0) (2024-10-02)


### ⚠ BREAKING CHANGES

* Changed the signature of RequireResources() method. We now return a slice of missing resources ([#24](https://github.com/cccteam/access/issues/24))

### Code Refactoring

* Changed the signature of RequireResources() method. We now return a slice of missing resources ([#24](https://github.com/cccteam/access/issues/24)) ([3bf3e6b](https://github.com/cccteam/access/commit/3bf3e6b20e7e24f9f0c56eac88913867761c20ec))
* Move resourcestore package to a new location ([#24](https://github.com/cccteam/access/issues/24)) ([3bf3e6b](https://github.com/cccteam/access/commit/3bf3e6b20e7e24f9f0c56eac88913867761c20ec))

## [0.3.0](https://github.com/cccteam/access/compare/v0.2.0...v0.3.0) (2024-09-17)


### ⚠ BREAKING CHANGES

* Package resourceset was moved to httpio repository ([#22](https://github.com/cccteam/access/issues/22))
* Package accesstypes was moved to ccc repository ([#22](https://github.com/cccteam/access/issues/22))

### Features

* Implemented resource permission checking ([#22](https://github.com/cccteam/access/issues/22)) ([0a81179](https://github.com/cccteam/access/commit/0a811797d2f2a22b92d73d2f37baeacdb8db5bf7))


### Code Refactoring

* Package accesstypes was moved to ccc repository ([#22](https://github.com/cccteam/access/issues/22)) ([0a81179](https://github.com/cccteam/access/commit/0a811797d2f2a22b92d73d2f37baeacdb8db5bf7))
* Package resourceset was moved to httpio repository ([#22](https://github.com/cccteam/access/issues/22)) ([0a81179](https://github.com/cccteam/access/commit/0a811797d2f2a22b92d73d2f37baeacdb8db5bf7))

## [0.2.0](https://github.com/cccteam/access/compare/v0.1.4...v0.2.0) (2024-09-11)


### ⚠ BREAKING CHANGES

* Refactored the interface for consistency and adding in support for Resources ([#13](https://github.com/cccteam/access/issues/13))

### Features

* Implement Resources in Casbin ([#13](https://github.com/cccteam/access/issues/13)) ([0bbf51a](https://github.com/cccteam/access/commit/0bbf51a1c44d73e2c876b88c3bc169a06cc5db37))


### Code Refactoring

* Refactored the interface for consistency and adding in support for Resources ([#13](https://github.com/cccteam/access/issues/13)) ([0bbf51a](https://github.com/cccteam/access/commit/0bbf51a1c44d73e2c876b88c3bc169a06cc5db37))

## [0.1.4](https://github.com/cccteam/access/compare/v0.1.3...v0.1.4) (2024-09-10)


### Features

* Move resource type to acesstype package ([#17](https://github.com/cccteam/access/issues/17)) ([ef4cb59](https://github.com/cccteam/access/commit/ef4cb5965ae343aa50d4d8be6ad21a6d848935aa))

## [0.1.3](https://github.com/cccteam/access/compare/v0.1.2...v0.1.3) (2024-08-30)


### Features

* Implement resource store ([#10](https://github.com/cccteam/access/issues/10)) ([ba58817](https://github.com/cccteam/access/commit/ba58817e15a4985811fec3a73345b05a2505ad09))

## [0.1.2](https://github.com/cccteam/access/compare/v0.1.1...v0.1.2) (2024-08-29)


### Features

* Implementation of resourceset ([#9](https://github.com/cccteam/access/issues/9)) ([871dcf4](https://github.com/cccteam/access/commit/871dcf414b04b1bd57ee333863b1900694a5a446))
* New accesstypes package ([#7](https://github.com/cccteam/access/issues/7)) ([b7d703b](https://github.com/cccteam/access/commit/b7d703b2ca8ac7143865450e38a73912abaaa765))

## [0.1.1](https://github.com/cccteam/access/compare/v0.1.0...v0.1.1) (2024-08-27)


### Bug Fixes

* Fix spelling issue ([#4](https://github.com/cccteam/access/issues/4)) ([bae69ab](https://github.com/cccteam/access/commit/bae69ab38148470927d0494fcf8d5eca72e3ae3d))

## 0.1.0 (2024-08-27)


### Features

* Initial release ([#3](https://github.com/cccteam/access/issues/3)) ([2ecf15f](https://github.com/cccteam/access/commit/2ecf15f12ddf185ff803084eab1a94ce90e60ca4))
* Update README ([#1](https://github.com/cccteam/access/issues/1)) ([78d919b](https://github.com/cccteam/access/commit/78d919b52c39ba0f264ab4682479107f43ae67a1))
