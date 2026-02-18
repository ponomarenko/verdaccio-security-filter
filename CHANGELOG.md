# Changelog

## [1.3.5](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.3.4...v1.3.5) (2026-02-18)


### Bug Fixes

* **filter:** wire checkVersionAge into filter_metadata for minVersionAgeDays ([#36](https://github.com/ponomarenko/verdaccio-security-filter/issues/36)) ([bc10561](https://github.com/ponomarenko/verdaccio-security-filter/commit/bc10561daac3939cdcbd51decb0781a23a95069b)), closes [#29](https://github.com/ponomarenko/verdaccio-security-filter/issues/29)

## [1.3.4](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.3.3...v1.3.4) (2026-02-18)


### Bug Fixes

* **deps:** pin qs to 6.14.2 to fix CVE-2025-15284 ([#33](https://github.com/ponomarenko/verdaccio-security-filter/issues/33)) ([29b5e3a](https://github.com/ponomarenko/verdaccio-security-filter/commit/29b5e3a3a99700591f732b2972dcd4c9e127bdb5))

## [1.3.3](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.3.2...v1.3.3) (2026-01-02)


### Bug Fixes

* resolve high-severity DoS vulnerability in qs dependency ([#26](https://github.com/ponomarenko/verdaccio-security-filter/issues/26)) ([d54300b](https://github.com/ponomarenko/verdaccio-security-filter/commit/d54300be77f707f22f21f673a109e71cba416f5d))

## [1.3.2](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.3.1...v1.3.2) (2025-12-29)


### Performance Improvements

* optimize package size by 34% ([#24](https://github.com/ponomarenko/verdaccio-security-filter/issues/24)) ([a75b7a4](https://github.com/ponomarenko/verdaccio-security-filter/commit/a75b7a4162a27037a24d6820609adf85d35e9969))

## [1.3.1](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.3.0...v1.3.1) (2025-12-29)


### Bug Fixes

* resolve critical memory leaks causing heap exhaustion ([#22](https://github.com/ponomarenko/verdaccio-security-filter/issues/22)) ([ffaaabc](https://github.com/ponomarenko/verdaccio-security-filter/commit/ffaaabc6039069add1de574faf429f10219f363e))

## [1.3.0](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.2.0...v1.3.0) (2025-12-22)


### Features

* add author and region-based package filtering ([#19](https://github.com/ponomarenko/verdaccio-security-filter/issues/19)) ([64597b8](https://github.com/ponomarenko/verdaccio-security-filter/commit/64597b8495272374dbba877b8de5e31c454b21d0))

## [1.2.0](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.1.0...v1.2.0) (2025-12-13)


### Features

* enable release-please automation ([c5153f0](https://github.com/ponomarenko/verdaccio-security-filter/commit/c5153f0d1ab6c0d1a6241386b59355d777571a19))


### Bug Fixes

* add provenance for npm trusted publishing ([9c73e9a](https://github.com/ponomarenko/verdaccio-security-filter/commit/9c73e9a10075ae43eb1343bda0dbe81353db8da1))
* configure OIDC permissions for npm publishing ([120b058](https://github.com/ponomarenko/verdaccio-security-filter/commit/120b05815f6f52a376a47c9d39fbd60f5f4c65f6))
* remove needs dependency in publish job ([dc4561d](https://github.com/ponomarenko/verdaccio-security-filter/commit/dc4561d3fa0668de6b079560c26f6fd1b61f00fb))
* revert codecov action to v5 ([449c815](https://github.com/ponomarenko/verdaccio-security-filter/commit/449c8151418abb7beb7be0ed7d50ecbe1444ea69))

## [1.1.0](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.6...v1.1.0) (2025-12-13)


### Features

* implement high-priority improvements for production readiness ([#16](https://github.com/ponomarenko/verdaccio-security-filter/issues/16)) ([afa174c](https://github.com/ponomarenko/verdaccio-security-filter/commit/afa174c841b2c1823dfc907e81316d2f3075b9aa))

## [1.0.6](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.5...v1.0.6) (2025-12-13)


### Bug Fixes

* add NPM_TOKEN for initial package publication ([d694418](https://github.com/ponomarenko/verdaccio-security-filter/commit/d694418df1106e250dbc21550dee35bc71d14aee))

## [1.0.5](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.4...v1.0.5) (2025-12-13)


### Bug Fixes

* add provenance flag for OIDC publishing ([089c8fb](https://github.com/ponomarenko/verdaccio-security-filter/commit/089c8fb58ac4d3ee6dbd3452c85213144b73cb97))

## [1.0.4](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.3...v1.0.4) (2025-12-13)


### Bug Fixes

* consolidate workflow permissions and add public access flag ([#10](https://github.com/ponomarenko/verdaccio-security-filter/issues/10)) ([9f00dc8](https://github.com/ponomarenko/verdaccio-security-filter/commit/9f00dc824e9ee21abb6e3c82ac99e36a440881b0))

## [1.0.3](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.2...v1.0.3) (2025-12-13)


### Bug Fixes

* update jws dependency to resolve security vulnerability ([#8](https://github.com/ponomarenko/verdaccio-security-filter/issues/8)) ([99ddcee](https://github.com/ponomarenko/verdaccio-security-filter/commit/99ddceeb95e5e513067991b6803ce1cd7a4c7a69))

## [1.0.2](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.1...v1.0.2) (2025-12-13)


### Bug Fixes

* add npm token and dual registry publishing support ([#5](https://github.com/ponomarenko/verdaccio-security-filter/issues/5)) ([d09157f](https://github.com/ponomarenko/verdaccio-security-filter/commit/d09157fa7ae99734b30656ef6fcd5ce7af9f0c41))

## [1.0.1](https://github.com/ponomarenko/verdaccio-security-filter/compare/v1.0.0...v1.0.1) (2025-12-13)


### Bug Fixes

* remove NPM_TOKEN for OIDC authentication ([#3](https://github.com/ponomarenko/verdaccio-security-filter/issues/3)) ([28a234c](https://github.com/ponomarenko/verdaccio-security-filter/commit/28a234cb0396cfff9b7c49e067ad8fd26fffab93))

## 1.0.0 (2025-12-13)


### Features

* add publish workflow for automated package publishing on release ([f6e3d14](https://github.com/ponomarenko/verdaccio-security-filter/commit/f6e3d14ecc860e64e33246affea1a45b3b518377))
* implement comprehensive security filtering system with dual-layer protection ([d17887c](https://github.com/ponomarenko/verdaccio-security-filter/commit/d17887cd2f37e8461c70de588e8cf66defee1906))
* initialize verdaccio-customname plugin with basic structure ([1ef2bcf](https://github.com/ponomarenko/verdaccio-security-filter/commit/1ef2bcf4dda879cd0d7f01a3c4a3040e24675ba8))
* refactor verdaccio plugin to implement security filtering ([97b78de](https://github.com/ponomarenko/verdaccio-security-filter/commit/97b78de8b401fc65e55749fc81131f5bb5534e6b))


### Bug Fixes

* add id-token permission to publish job in workflow ([41e5762](https://github.com/ponomarenko/verdaccio-security-filter/commit/41e576269c6581a2e385f3835e022dfbbc160f58))
* downgrade Node.js version to 22.x in workflow for compatibility ([2935480](https://github.com/ponomarenko/verdaccio-security-filter/commit/293548055da42f36eea22078abd586c09a8886bc))
* remove deprecated npm publish workflow file ([032a29f](https://github.com/ponomarenko/verdaccio-security-filter/commit/032a29facdae6539b2dae7887b85f8d313fa39eb))
* update author information and repository URLs in package.json ([8bdb090](https://github.com/ponomarenko/verdaccio-security-filter/commit/8bdb09055bec85c68aad504e08d4cdace1e73298))
* update metadata validation to remove version check ([36d4160](https://github.com/ponomarenko/verdaccio-security-filter/commit/36d4160ecaad445e4a15864f6889b449851d2111))
* update package name to include scope in package.json and package-lock.json ([62e01cb](https://github.com/ponomarenko/verdaccio-security-filter/commit/62e01cbeb0c1373fab22948fd3b4f4fc7b117984))
* update package name to remove scope and adjust Node.js version in workflows ([25932cf](https://github.com/ponomarenko/verdaccio-security-filter/commit/25932cfaf7c627bddd4b4e647ce50ef41d701b24))
* update repository URL format in package.json and remove unused globals dependency from package-lock.json ([ef3d38a](https://github.com/ponomarenko/verdaccio-security-filter/commit/ef3d38a5d024943a6dde43f112d93d723da17fa7))
* update workflow name and enhance npm publish command with provenance and access options ([2ab4fba](https://github.com/ponomarenko/verdaccio-security-filter/commit/2ab4fbaec0fbca4ff0fc709431ec5fefe0880ac4))
* update workflow name and streamline publish job steps ([5e5467b](https://github.com/ponomarenko/verdaccio-security-filter/commit/5e5467b40138dfce11c95fa2dc26fe238f4df2d7))
* update workflow trigger to 'created' and streamline npm publish steps ([69696a6](https://github.com/ponomarenko/verdaccio-security-filter/commit/69696a6149d726eee5a4cb51af1991d4e794d90b))
* use PAT_TOKEN for release-please to enable PR creation ([#1](https://github.com/ponomarenko/verdaccio-security-filter/issues/1)) ([0eb3245](https://github.com/ponomarenko/verdaccio-security-filter/commit/0eb324596a0c809fae417b17cfd63189a948d34b))

## [1.0.0](https://github.com/ponomarenko/verdaccio-security-filter/compare/v0.0.0...v1.0.0) (2025-01-15)


### Features

* implement comprehensive security filtering system with dual-layer protection ([d17887c](https://github.com/ponomarenko/verdaccio-security-filter/commit/d17887c))
* add publish workflow for automated package publishing on release ([f6e3d14](https://github.com/ponomarenko/verdaccio-security-filter/commit/f6e3d14))


### Continuous Integration

* improve npm publishing workflow and package configuration ([bc8cb57](https://github.com/ponomarenko/verdaccio-security-filter/commit/bc8cb57))


### Bug Fixes

* update workflow name and streamline publish job steps ([5e5467b](https://github.com/ponomarenko/verdaccio-security-filter/commit/5e5467b))
* remove deprecated npm publish workflow file ([032a29f](https://github.com/ponomarenko/verdaccio-security-filter/commit/032a29f))
