# Changelog

## [0.9.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.8.0...typescript-v0.9.0) (2026-09-03)


### Features

* **typescript:** correct stale v0.3.0 pin comment after v0.4.0 bump ([5505a10](https://github.com/bytepunx/signet-clients/commit/5505a10b4199147f3d872a3e839960ed4ac440bd))


### Bug Fixes

* **ci:** make proto-bump releases actually trigger, stop committing build artifacts ([49be699](https://github.com/bytepunx/signet-clients/commit/49be699e2c6a3e665015968b9cb1a5b253fc3978))

## [0.8.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.7.0...typescript-v0.8.0) (2026-09-01)


### Features

* **typescript:** expose GitOpsService over workload SPIFFE mTLS ([3790225](https://github.com/bytepunx/signet-clients/commit/3790225a8974ad143c61b4e8712f573d6d1cf26e))

## [0.7.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.6.0...typescript-v0.7.0) (2026-08-21)


### Features

* **typescript:** regenerate for GitOpsService.GetServiceConfig ([09c8922](https://github.com/bytepunx/signet-clients/commit/09c89225a6066be8f36686f79819ce1b61caee47))


### Bug Fixes

* **typescript:** dialWorkload holds the event loop open during the SVID fetch ([72feeab](https://github.com/bytepunx/signet-clients/commit/72feeab58644f5435ff8f312a84ab6c7fbd6dc5d))

## [0.6.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.5.0...typescript-v0.6.0) (2026-08-15)


### Features

* **typescript:** add encryptForSecret for client-side SOPS encryption ([#52](https://github.com/bytepunx/signet-clients/issues/52)) ([8614bf9](https://github.com/bytepunx/signet-clients/commit/8614bf9921da527ed04e1778e4898a00bfab0020))

## [0.5.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.4.1...typescript-v0.5.0) (2026-08-14)


### Features

* **typescript:** add JSON Patch helper constructors for PatchServiceConfig ([cd14a18](https://github.com/bytepunx/signet-clients/commit/cd14a1857e944501175dff7e80418635a3f8c7db))

## [0.4.1](https://github.com/bytepunx/signet-clients/compare/typescript-v0.4.0...typescript-v0.4.1) (2026-08-09)


### Bug Fixes

* **typescript:** add repository field to package.json for npm Trusted Publishing ([#45](https://github.com/bytepunx/signet-clients/issues/45)) ([b051350](https://github.com/bytepunx/signet-clients/commit/b051350e05ac87914623f8780898f7b2a74e727e))

## [0.4.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.3.0...typescript-v0.4.0) (2026-08-08)


### Features

* **csharp:** mirror the plaintext admin-dial option and default workload-dial retry ([41240bd](https://github.com/bytepunx/signet-clients/commit/41240bd45c0da021bf0aec2a81a0495db9129efd))
* **go:** mirror the plaintext admin-dial option and default workload-dial retry ([dde6c54](https://github.com/bytepunx/signet-clients/commit/dde6c5449c0678cce8993e3b43b7f06a2ca9bdde))
* **rust:** mirror the plaintext admin-dial option and default workload-dial retry ([0bd7494](https://github.com/bytepunx/signet-clients/commit/0bd7494291ac69649294c204a3e77401997d6611))
* **typescript:** mirror the plaintext admin-dial option and default workload-dial retry ([6f19c98](https://github.com/bytepunx/signet-clients/commit/6f19c981468dfdf8a962553c5ca13e1f35471df4))

## [0.3.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.2.0...typescript-v0.3.0) (2026-07-20)


### Features

* add automated package publishing for all five clients ([#24](https://github.com/bytepunx/signet-clients/issues/24)) ([1c8dee9](https://github.com/bytepunx/signet-clients/commit/1c8dee93eeac203b91c065420d53ef04ce350ce8))

## [0.2.0](https://github.com/bytepunx/signet-clients/compare/typescript-v0.1.0...typescript-v0.2.0) (2026-07-19)


### Features

* **examples:** fetch a second, policy-granted bundle in each echo service ([#16](https://github.com/bytepunx/signet-clients/issues/16)) ([26f58b8](https://github.com/bytepunx/signet-clients/commit/26f58b8d1860aa712c26d93fe48408c2254ec91e))
