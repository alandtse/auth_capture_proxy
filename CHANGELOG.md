# CHANGELOG


## v1.3.4 (2026-01-31)

### Bug Fixes

* fix: add httpx timeout (#31) ([`4808ca7`](https://github.com/alandtse/auth_capture_proxy/commit/4808ca714f1756dec3d0f88b32a24363141eb403))

### Continuous Integration

* ci: update deprecated runners and action versions (#36)

Co-authored-by: alandtse <7086117+alandtse@users.noreply.github.com>
Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com> ([`ef35963`](https://github.com/alandtse/auth_capture_proxy/commit/ef35963e07d98140fa03b0ed6b244c7db0807ede))

* ci: bump versions ([`149906c`](https://github.com/alandtse/auth_capture_proxy/commit/149906c241a8a147385eebbe98894a068b04c49b))


## v1.3.3 (2024-11-28)

### Bug Fixes

* fix: preconfigure SSL context

closes #28 ([`5159165`](https://github.com/alandtse/auth_capture_proxy/commit/5159165ed6088134dedc1bb1a950a6894fbc2465))

### Continuous Integration

* ci: bump checkout to v4 (#30) ([`2f0dea6`](https://github.com/alandtse/auth_capture_proxy/commit/2f0dea6f08d595fd14bfbaf24ba0657a921354da))


## v1.3.2 (2023-11-29)

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`b3ef461`](https://github.com/alandtse/auth_capture_proxy/commit/b3ef461e9ae38da591ab9315466b607a18bbaf74))


## v1.3.1 (2023-11-29)

### Bug Fixes

* fix: change base_url path warning to debug ([`68af0dd`](https://github.com/alandtse/auth_capture_proxy/commit/68af0dd94d45d8143dcf93bddee28ed6961394c7))

* fix: automatically convert base_url from file url

The base url for prepend_url had undefined behavior if the url pointed
to a file (e.g., did not end with a /). Now this is detected and will be
converted.
`http://www.domain.com/path/to` -> `http://www.domain.com/path/to/`

This was necessary so the appended url would be added to the path.
`http://www.domain.com/path/to/` + `new_path` ->
`http://www.domain.com/path/to/new_path` instead of
`http://www.domain.com/path/tonew_path

https://github.com/alandtse/alexa_media_player/issues/2111 ([`08a396d`](https://github.com/alandtse/auth_capture_proxy/commit/08a396d6d8ca63c43f5eded5955b24f66187093d))


## v1.3.0 (2023-11-26)

### Build System

* build: ignore cff-version pattern ([`82d2e8e`](https://github.com/alandtse/auth_capture_proxy/commit/82d2e8e7329b1115870ef2677e6de950fae52155))

* build: update versions across other files ([`3496860`](https://github.com/alandtse/auth_capture_proxy/commit/34968602511b3c13675e8941ee96b59423942c4f))

### Continuous Integration

* ci: Delete .github/workflows/checks.yml (#27) ([`65bf363`](https://github.com/alandtse/auth_capture_proxy/commit/65bf3630948cda9aec945633f0a40dca78700549))

* ci: add 3.12 to pr test ([`2da9bb6`](https://github.com/alandtse/auth_capture_proxy/commit/2da9bb6fc6fb1bd6d628b9115fef17ce1552897d))

### Features

* feat: preserve custom headers and allow dynamic sessions

Preserving custom headers & dynamic session instantiation for bypassing more secure CSRF defense systems (#26). These changes also make it possible to host the MITM site in a subdomain or subdirectory. This feature was required for a project of mine and more people may benefit from its inclusion in the library. ([`307bd06`](https://github.com/alandtse/auth_capture_proxy/commit/307bd06f36cde09810f5511d67438bd95aa78f68))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`2e92f00`](https://github.com/alandtse/auth_capture_proxy/commit/2e92f0010fd5c8a6de33982898c01584545dec9b))

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`538fc1d`](https://github.com/alandtse/auth_capture_proxy/commit/538fc1de60e86f35aac3c730a0465da12f1c1b84))


## v1.2.1 (2023-11-25)

### Build System

* build: do not ping importlib ([`2790c06`](https://github.com/alandtse/auth_capture_proxy/commit/2790c06909cfd84263f91c1595b4db552c4c0ec0))

* build: fix docs command ([`40428ae`](https://github.com/alandtse/auth_capture_proxy/commit/40428ae38fd07aadc563ff6588f69a5f4462113e))

* build: update tox tests ([`7f79611`](https://github.com/alandtse/auth_capture_proxy/commit/7f796111b4dc53541326a9b9ed32e46b7b5b17b5))

* build: update to pytest 3.7 ([`fbf3031`](https://github.com/alandtse/auth_capture_proxy/commit/fbf3031d664cb90bdd51623917e746991d019d49))

### Continuous Integration

* ci: add tox-gh-actions ([`de4d665`](https://github.com/alandtse/auth_capture_proxy/commit/de4d665536851bc1f933cdf8e8ef09f7d91cc16a))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`61f394e`](https://github.com/alandtse/auth_capture_proxy/commit/61f394e37e91473565ac3a437ca52fec9d8ae3f9))


## v1.2.0 (2023-05-08)

### Bug Fixes

* fix: fix multiple / detection in urls

Switch to regex instead of replace to handle `///` ([`2352e22`](https://github.com/alandtse/auth_capture_proxy/commit/2352e22cabcf9c5fb39499f588026bac2462d18d))

### Build System

* build: bump deps ([`7c91f3c`](https://github.com/alandtse/auth_capture_proxy/commit/7c91f3c911570e2d3fd579b75805525eaf04f0be))

### Continuous Integration

* ci: lock psr 7.34.6 ([`fc2f4ce`](https://github.com/alandtse/auth_capture_proxy/commit/fc2f4ce3ece425924309da11001a3380a9069a49))

* ci: convert python-version to string ([`ea4447b`](https://github.com/alandtse/auth_capture_proxy/commit/ea4447b2a9f824884470e7fbb3a55a9d774a254d))

### Testing

* test: fix test_return_timer_countdown_refresh_html

Handle the case where the text is "".

closes #25 ([`8b759c1`](https://github.com/alandtse/auth_capture_proxy/commit/8b759c1bb4785ed3ac24dea7120b1379e1928f1a))

* test: add tests for urls with trailing / ([`9fdb6af`](https://github.com/alandtse/auth_capture_proxy/commit/9fdb6af0f8c655c88ba9ae553e3568eed21f38aa))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`2e4606a`](https://github.com/alandtse/auth_capture_proxy/commit/2e4606a00a98b3dbe18705644be3275aebafefac))


## v1.1.6 (2023-05-08)

### Features

* feat: require python 3.10 ([`9ede8e1`](https://github.com/alandtse/auth_capture_proxy/commit/9ede8e1961d9cd3ee188bd8145810c1003a004a3))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`a4bea86`](https://github.com/alandtse/auth_capture_proxy/commit/a4bea8601d228cbef9ec2147962ea35ac3e0b62a))


## v1.1.5 (2023-05-07)

### Bug Fixes

* fix: require python 3.9 or greater ([`5ba1afd`](https://github.com/alandtse/auth_capture_proxy/commit/5ba1afdaf2cbdf16a82c7f40d2d56d145b8b369f))

* fix(access_url): do not add port if 0 ([`ba9acb4`](https://github.com/alandtse/auth_capture_proxy/commit/ba9acb49f106a76c32f95ef3ef871444309597e0))

### Build System

* build: replace deprecated use of whitelist ([`2cc1244`](https://github.com/alandtse/auth_capture_proxy/commit/2cc1244ed9b08db9c723dd3b9789164d2c5f1fef))

* build: bump deps ([`b59c41e`](https://github.com/alandtse/auth_capture_proxy/commit/b59c41ed2e283e9eb78ffba2ca70d4df6734738e))

### Code Style

* style: fix implicit optionals ([`c703521`](https://github.com/alandtse/auth_capture_proxy/commit/c703521872ba8848338203ad8a9d1cfeffd6a06c))

### Continuous Integration

* ci: unpin PSR ([`bcb15d6`](https://github.com/alandtse/auth_capture_proxy/commit/bcb15d6eaeacfe49fa800c82c564134d88b4b34b))

### Testing

* test: fix ports to use valid values ([`896e099`](https://github.com/alandtse/auth_capture_proxy/commit/896e09946ba4fb6f8ca38ce72936ca38bc8a3d7f))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy ([`8c91915`](https://github.com/alandtse/auth_capture_proxy/commit/8c91915a16445c800743602347810462da9a019f))


## v1.1.4 (2022-06-25)

### Bug Fixes

* fix: fix swap_url for http converted urls ([`2b672fa`](https://github.com/alandtse/auth_capture_proxy/commit/2b672fa3a9c86ecf4dd64d7fc7d66a8a7fa1d5ff))

### Build System

* build: relax dep versions ([`d131894`](https://github.com/alandtse/auth_capture_proxy/commit/d1318941215a3c8c328d34db141de9fd92dee810))

* build: update deps ([`b457b25`](https://github.com/alandtse/auth_capture_proxy/commit/b457b25868a212d7396c6e6baebac5e3e40f265c))

* build: bump deps ([`a1cff32`](https://github.com/alandtse/auth_capture_proxy/commit/a1cff32e100e0346c276c3bd2ac2acee0c6f3a18))

* build: update pre-commit checks ([`aa6083c`](https://github.com/alandtse/auth_capture_proxy/commit/aa6083c3f4b12497c47858ce71b1206c584b840b))

* build: bump black in pre-commit ([`56321eb`](https://github.com/alandtse/auth_capture_proxy/commit/56321ebf98040225bbe7f86e6c6d8027246b0d8e))

* build: bump deps ([`abce32f`](https://github.com/alandtse/auth_capture_proxy/commit/abce32f83890515ddd7583eaf827c4102fced20f))

* build(deps): bump httpx from 0.22.0 to 0.23.0

Bumps [httpx](https://github.com/encode/httpx) from 0.22.0 to 0.23.0.
- [Release notes](https://github.com/encode/httpx/releases)
- [Changelog](https://github.com/encode/httpx/blob/master/CHANGELOG.md)
- [Commits](https://github.com/encode/httpx/compare/0.22.0...0.23.0)

---
updated-dependencies:
- dependency-name: httpx
  dependency-type: direct:production
...

Signed-off-by: dependabot[bot] <support@github.com> ([`7878bb4`](https://github.com/alandtse/auth_capture_proxy/commit/7878bb4764440b2d29a90bef076bb5708db3e461))

### Continuous Integration

* ci: pin psr to v7.28.1

https://github.com/relekang/python-semantic-release/issues/442 ([`f609a25`](https://github.com/alandtse/auth_capture_proxy/commit/f609a25beff7cb482f7682950dec81d97d45b72e))

* ci: add fetch-depth to semantic-release ([`980dc91`](https://github.com/alandtse/auth_capture_proxy/commit/980dc91701413fd01ac85bfa5193e351511c7b2a))

### Testing

* test: add tests for swap_url ([`3b6ff36`](https://github.com/alandtse/auth_capture_proxy/commit/3b6ff365d6f41a0bbca26d736acdda5bc7eac23d))

### Unknown

* Merge pull request #22 from alandtse/http_upgrade

Http upgrade ([`360c197`](https://github.com/alandtse/auth_capture_proxy/commit/360c1971efb20232ecc20167cd663fe1b690c301))


## v1.1.3 (2022-02-25)

### Bug Fixes

* fix: bump multidict

Resolves latest HA 2022.3 requirements. ([`bf8c7c1`](https://github.com/alandtse/auth_capture_proxy/commit/bf8c7c13252d2042f07a8ad2de1e6aba188e6985))


## v1.1.2 (2022-02-25)

### Bug Fixes

* fix: bump dependencies (#19) ([`76c9344`](https://github.com/alandtse/auth_capture_proxy/commit/76c9344d656bcff61996fb335b94ecf9c3b35804))

### Unknown

* Merge branch 'main' into ha_beta ([`954922d`](https://github.com/alandtse/auth_capture_proxy/commit/954922d94b59bb8981f30efe78995e9add587201))


## v1.1.1 (2021-11-23)

### Bug Fixes

* fix: enable redirect following (#18)

* fix: enable redirect following

* ci: change markdown check to changed files ([`0f011ac`](https://github.com/alandtse/auth_capture_proxy/commit/0f011accbb50412a54a9ca0a853cceb5a88a3ce6))

### Unknown

* Merge branch 'main' into redirects ([`2913909`](https://github.com/alandtse/auth_capture_proxy/commit/29139095883c83e58047b5c3c1d2fb3c24639cdc))


## v1.1.0 (2021-11-23)

### Bug Fixes

* fix: bump dependencies ([`59c8b25`](https://github.com/alandtse/auth_capture_proxy/commit/59c8b25d474229204f95d57d405214a2386c6e3e))

* fix: enable redirect following ([`2e9bc09`](https://github.com/alandtse/auth_capture_proxy/commit/2e9bc0956f3b8e15b00d75cf9ce08174165aa863))

* fix: only resume httpx sessions ([`b990bd4`](https://github.com/alandtse/auth_capture_proxy/commit/b990bd4a2414b0110f642024b99d3061f68682c1))

### Build System

* build: bump deps ([`8753022`](https://github.com/alandtse/auth_capture_proxy/commit/8753022ee87f669861ac639c8a09c2d0f1c501dc))

* build: update deps ([`03af35f`](https://github.com/alandtse/auth_capture_proxy/commit/03af35fc0a4a150bf0eb3a0b55087de58fdff66f))

### Code Style

* style: address lint ([`e0ff339`](https://github.com/alandtse/auth_capture_proxy/commit/e0ff33948c830c06ef4822b0ea2f8c39995e6813))

### Continuous Integration

* ci: change markdown check to changed files ([`498fa7b`](https://github.com/alandtse/auth_capture_proxy/commit/498fa7b2beb754ad5ac6fd0fa952ee4b797fa7e0))

* ci: revert coveralls action ([`eaa6410`](https://github.com/alandtse/auth_capture_proxy/commit/eaa64107d564ff658f3d2f46f40bae9171eab51f))

* ci: swap to coveralls action ([`7530e1b`](https://github.com/alandtse/auth_capture_proxy/commit/7530e1bc9adff3e4b1ae55ea357c55b2a13de826))

### Features

* feat: bump for release ([`9ff7b15`](https://github.com/alandtse/auth_capture_proxy/commit/9ff7b159e91902801345b95a0d9cdcf24e5a8d04))

* feat: add some parsing of aiohttp ClientReponse ([`59d91a3`](https://github.com/alandtse/auth_capture_proxy/commit/59d91a307c46daa0207b2a4a26e1372533f60480))

### Unknown

* feat (helper): allow flattening of multidict

Fake commit to bump
https://github.com/alandtse/auth_capture_proxy/commit/91723f6d4c6c25435fce7b7bfa4dd635060956d1
https://github.com/alandtse/auth_capture_proxy/commit/91723f6d4c6c25435fce7b7bfa4dd635060956d1 ([`5f96c4e`](https://github.com/alandtse/auth_capture_proxy/commit/5f96c4e5f4b6b599f4706d1d9ab3a64b0f94a91b))

* feat (helper): allow flattening of multidict ([`91723f6`](https://github.com/alandtse/auth_capture_proxy/commit/91723f6d4c6c25435fce7b7bfa4dd635060956d1))


## v1.0.2 (2021-08-10)

### Bug Fixes

* fix: fix multiple cookie error in debug (#17)

Print the cookie jar instead of trying to parse the cookies into a
dict.
Closes #16 ([`f1cd671`](https://github.com/alandtse/auth_capture_proxy/commit/f1cd671b63dd495b2c90aefd51c59a8fbc004cae))

* fix: fix multiple cookie error in debug
Print the cookie jar instead of trying to parse the cookies into a
dict.
Closes #16 ([`1e8a12c`](https://github.com/alandtse/auth_capture_proxy/commit/1e8a12ced83af5ae40718aae8c2f87796062fbf2))

### Build System

* build: update deps ([`74fc587`](https://github.com/alandtse/auth_capture_proxy/commit/74fc5876f9f6ebd885f4b95b65f169589c8777b1))

* build: loosen constraint on importlib-metadata ([`c67dd40`](https://github.com/alandtse/auth_capture_proxy/commit/c67dd40ecc86943481891c343f7286ccd93dcac9))

* build: change to poetry-core
closes #14 ([`832f264`](https://github.com/alandtse/auth_capture_proxy/commit/832f264a6feb70daa3b76954c72ff7113b89af0e))


## v1.0.1 (2021-05-01)

### Bug Fixes

* fix: relax dependency versions
^ notation for 0.x.y releases may be too strict ([`55c12ce`](https://github.com/alandtse/auth_capture_proxy/commit/55c12ce0ac96d232e1790824360d745ecbf27163))


## v1.0.0 (2021-04-27)

### Breaking

* fix: swap to httpx (#13)

aiohttp appears to have issues related to Akamai Global Host and developers
do not seem interested in resolving as a bug.
https://github.com/aio-libs/aiohttp/issues/5643

BREAKING CHANGE: API has changed due to use of httpx.
Modifiers, test_url, and other items that access aiohttp ClientResponse
will need to be fixed. ([`311e998`](https://github.com/alandtse/auth_capture_proxy/commit/311e998b287dc445d002e5e1aceebe17e82adb65))


## v0.8.1 (2021-04-03)

### Bug Fixes

* fix: export const (#12)

* fix: export const

* ci: lock semantic release to v7.14.0
https://github.com/relekang/python-semantic-release/issues/331 ([`afc6b7c`](https://github.com/alandtse/auth_capture_proxy/commit/afc6b7c50dcaca8e8ff3811672ce8610c376974a))

* fix: export const ([`67c7bef`](https://github.com/alandtse/auth_capture_proxy/commit/67c7beffeadbd37fe1892fc933e4a8f65c1add7b))

### Continuous Integration

* ci: lock semantic release to v7.14.0
https://github.com/relekang/python-semantic-release/issues/331 ([`eea79df`](https://github.com/alandtse/auth_capture_proxy/commit/eea79dff7846865562d8b6dcf2c85c1ff69a5548))


## v0.8.0 (2021-04-03)

### Features

* feat: allow disabling of header autogeneration (#11)

* feat: add timeout for client session connections

* feat: allow disabling of header autogeneration ([`3eade2d`](https://github.com/alandtse/auth_capture_proxy/commit/3eade2deedf82c96bbf90724f5eee8c8a8a70234))

* feat: allow disabling of header autogeneration ([`5e4d3af`](https://github.com/alandtse/auth_capture_proxy/commit/5e4d3af8b887f80cc3ac9ae7722f33e6802b2b67))

* feat: add timeout for client session connections ([`2111221`](https://github.com/alandtse/auth_capture_proxy/commit/211122107b35588fd7a74ced94b207501342b925))


## v0.7.1 (2021-03-29)

### Bug Fixes

* fix: fix filter on redirect detection (#10)

* fix: fix filter on redirect detection
Fixes bug where all redirects were filtered even without a regex match

* build: add coverage change ([`94fb40e`](https://github.com/alandtse/auth_capture_proxy/commit/94fb40e81b7a1cdb5c6cc85bad1d68c4802d9ff6))

* fix: fix filter on redirect detection
Fixes bug where all redirects were filtered even without a regex match ([`b666c0f`](https://github.com/alandtse/auth_capture_proxy/commit/b666c0f6ac720c8766668044b558c2412206b07f))

### Build System

* build: add coverage change ([`00b08b1`](https://github.com/alandtse/auth_capture_proxy/commit/00b08b116a7f7f0be45e9daaac9d8b2b20b1b9e5))


## v0.7.0 (2021-03-13)

### Bug Fixes

* fix: replace hosts if request.host changed
Fix issue where detected host is an ip address even if the access_url
is a domain
closes #1203 ([`d107828`](https://github.com/alandtse/auth_capture_proxy/commit/d1078280fdd3ff2f6a546be57ca962badaf7d00a))

### Features

* feat: add filter for check_redirects (#6)

* refactor: remove extraneous url check

* feat: add filter for check_redirects

* fix: replace hosts if request.host changed
Fix issue where detected host is an ip address even if the access_url
is a domain
closes #1203 ([`144147a`](https://github.com/alandtse/auth_capture_proxy/commit/144147a365293541a763d4a8957b57d1ed2c7aaa))

* feat: add filter for check_redirects ([`eed6ebc`](https://github.com/alandtse/auth_capture_proxy/commit/eed6ebce3417fda881e1845600a3496d6b127dd5))

### Refactoring

* refactor: remove extraneous url check ([`423c93b`](https://github.com/alandtse/auth_capture_proxy/commit/423c93bb03e52c3ff183c46bc3bb1afba6ca81e2))


## v0.6.0 (2021-03-01)

### Code Style

* style: remove extraneous space in debug logs ([`0b4940f`](https://github.com/alandtse/auth_capture_proxy/commit/0b4940f2eb988b815df5285044f0646db303433a))

### Features

* feat: change host when redirect detected

* style: remove extraneous space in debug logs

* feat: allow selecting hard refresh for timer

* refactor: remove extra space in debug logs

* feat: change host when redirect detected

* test: update coverage ([`1d6fa10`](https://github.com/alandtse/auth_capture_proxy/commit/1d6fa10085a0f7ccd049caa2a0d3778c12a276fc))

* feat: change host when redirect detected ([`6bf2d58`](https://github.com/alandtse/auth_capture_proxy/commit/6bf2d58812c9ea41179639c42327accbb23ab140))

* feat: allow selecting hard refresh for timer ([`d6a0d08`](https://github.com/alandtse/auth_capture_proxy/commit/d6a0d081420fd1138e0eb66f6dccb47127cf37ef))

### Refactoring

* refactor: remove extra space in debug logs ([`56e94ad`](https://github.com/alandtse/auth_capture_proxy/commit/56e94adb29b3f3fd41103ac648d27168e40d88e7))

### Testing

* test: update coverage ([`262a1c8`](https://github.com/alandtse/auth_capture_proxy/commit/262a1c8fb4200c62478c41f58fbd098153895c59))


## v0.5.0 (2021-02-25)

### Bug Fixes

* fix: handle null case for modifiers ([`388c6df`](https://github.com/alandtse/auth_capture_proxy/commit/388c6df8bc528dc29b1dec5c6820ced73ac573c4))

* fix: prevent autoreload from looping
Autoreload could force continuous reloads when a reload took too long. ([`01cd09c`](https://github.com/alandtse/auth_capture_proxy/commit/01cd09c1c5d4dc9160e807e650ee8c034864796f))

### Code Style

* style: add typing for stackoverflow ([`aab19c7`](https://github.com/alandtse/auth_capture_proxy/commit/aab19c793db097b20ec46e08070a90d33799c33c))

### Features

* feat: process multipart/form-data (#4)

Signed-off-by: Alan Tse <alandtse@gmail.com> ([`d9fc558`](https://github.com/alandtse/auth_capture_proxy/commit/d9fc558347df82f45330a76c04969d3e99b25717))

* feat: process multipart/form-data ([`1f3e6e9`](https://github.com/alandtse/auth_capture_proxy/commit/1f3e6e9de0ed908a6b2850d70973fc6abcdd2a03))

### Testing

* test: add tests for stackoverflow ([`51722b8`](https://github.com/alandtse/auth_capture_proxy/commit/51722b8de117dacb2766dd004e4419bb7d931b82))


## v0.4.2 (2021-02-20)

### Bug Fixes

* fix: bump dependencies ([`6e9dfd8`](https://github.com/alandtse/auth_capture_proxy/commit/6e9dfd89a059c3c272ad2be0ec4da3f6f439a0ce))

* fix: fix default refresh with legacy modifiers ([`b2fd0d5`](https://github.com/alandtse/auth_capture_proxy/commit/b2fd0d53efedf6eed61da42bda7973d0ccc24ca9))

* fix: skip non-modifiable files from reading ([`6fd9804`](https://github.com/alandtse/auth_capture_proxy/commit/6fd980420c7cf767a3560d45f3315d93168133e3))

### Build System

* build(deps): add isort ([`bdec356`](https://github.com/alandtse/auth_capture_proxy/commit/bdec356fc8ecb47dff68eacce29e7c5202554fe1))

### Code Style

* style: fix isort errors ([`f63b981`](https://github.com/alandtse/auth_capture_proxy/commit/f63b981a8b6675bec8363baab21011c313fadc6c))

* style: fix lint errors ([`f02ff19`](https://github.com/alandtse/auth_capture_proxy/commit/f02ff1996215493fe322e555f1e3a285b4d9e61a))

### Continuous Integration

* ci: add coveralls and coverage to push and pull ([`c096f79`](https://github.com/alandtse/auth_capture_proxy/commit/c096f79d4cbfcf474ef21fef272036aba318a105))

* ci: install poetry deps as commands_pre ([`6c949e8`](https://github.com/alandtse/auth_capture_proxy/commit/6c949e827cd6fc8d3b6daff09aa606027064ad9d))

* ci: break apart tox environments ([`c80c880`](https://github.com/alandtse/auth_capture_proxy/commit/c80c8809bf32cc52435e7b549c41e388271b5fa7))

* ci: add code coverage action ([`4f5dbdd`](https://github.com/alandtse/auth_capture_proxy/commit/4f5dbddd82e7a9b27c63aca8486dc61b8cffa561))

* ci: add tox-gh-actinos to workflow ([`34fd443`](https://github.com/alandtse/auth_capture_proxy/commit/34fd44375ade8bff34fb13d005687c7addc8a299))

* ci: allow parallel runs ([`6e93f49`](https://github.com/alandtse/auth_capture_proxy/commit/6e93f49acff8c4686feb7acceb32574ad1f98d90))

* ci: add tox-gh-actions ([`93cbaf0`](https://github.com/alandtse/auth_capture_proxy/commit/93cbaf0a7e531c905d6530f1e09aad228c562e36))

* ci: add additional python versions

Signed-off-by: Alan Tse <alandtse@gmail.com> ([`7224b1b`](https://github.com/alandtse/auth_capture_proxy/commit/7224b1b717e34e82e6950209c104a4e940bd8cf8))

### Features

* feat: allow modifiers per content_type ([`ace5e98`](https://github.com/alandtse/auth_capture_proxy/commit/ace5e98083cdb484df44d54dd9fcd410afb11a65))

* feat: allow encoding for prepend_url ([`339a5e6`](https://github.com/alandtse/auth_capture_proxy/commit/339a5e6c3e35dc4a2ef1d8417b17d649aab23614))

### Unknown

* Blank action (#3)

Signed-off-by: Alan Tse <alandtse@gmail.com> ([`b8f90e2`](https://github.com/alandtse/auth_capture_proxy/commit/b8f90e2f59fe447443e9a49a682355026d42402f))

* Merge branch 'main' into blank_action ([`4c37901`](https://github.com/alandtse/auth_capture_proxy/commit/4c379018dcdf4f967a27ef03d39cd412ffd3f91c))

* Merge branch 'main' into blank_action ([`b5b7ff8`](https://github.com/alandtse/auth_capture_proxy/commit/b5b7ff80e7dd235e0ac21bf03d69d1b27719d61a))


## v0.4.1 (2021-02-13)

### Bug Fixes

* fix: process src attribute in img tag ([`a00f995`](https://github.com/alandtse/auth_capture_proxy/commit/a00f995d3aebaa8714db8cc0e8b71754a0ce1429))

* fix: find nested html in script tags ([`cd1ed20`](https://github.com/alandtse/auth_capture_proxy/commit/cd1ed203986cdd40c10561784b6e13e969e5b7b0))

* fix: fix conversion of str args to URL ([`300cbf4`](https://github.com/alandtse/auth_capture_proxy/commit/300cbf4e1895c009744dfbdc9805aad3e0b304e2))

* fix: allow url to be empty string ([`ca5d3e2`](https://github.com/alandtse/auth_capture_proxy/commit/ca5d3e27e3d216d178d34f67254cdeb48b0457fa))

* fix: expose prepend and swap_url ([`2ea2b16`](https://github.com/alandtse/auth_capture_proxy/commit/2ea2b16f07bbf15926de06efb56b15393f9d9196))

* fix: fix imports ([`7263553`](https://github.com/alandtse/auth_capture_proxy/commit/7263553062c38df294ab73c2703a50c74e8fe789))

* fix: fix return_timer_countdown_refresh_htm import ([`943f24e`](https://github.com/alandtse/auth_capture_proxy/commit/943f24efd5afa322923e004d5146ae992d9ffa58))

### Build System

* build: require passing of flake and mypy ([`86303e7`](https://github.com/alandtse/auth_capture_proxy/commit/86303e785aaec2b418560657c068c0d72f97ffa2))

* build: fix today_fmt bug for sphinx ([`6e69762`](https://github.com/alandtse/auth_capture_proxy/commit/6e697624b141be011eefef8b3baa3dbc67ad9bfb))

* build(deps): bump deps ([`72eb76a`](https://github.com/alandtse/auth_capture_proxy/commit/72eb76ad768de6f7485875f084828154d6e88486))

### Documentation

* docs: fix changelog ([`7b9e79e`](https://github.com/alandtse/auth_capture_proxy/commit/7b9e79e8dd3cbd82be7b3ea7791234c176ba07da))

### Features

* feat: handle empty action attributes in form tags ([`b8de7e6`](https://github.com/alandtse/auth_capture_proxy/commit/b8de7e6ce20ff53de78621e8a566100a5744919f))

### Refactoring

* refactor: provide information about passthru urls ([`1e535d9`](https://github.com/alandtse/auth_capture_proxy/commit/1e535d99b97791325198b87defca98766c4ae43a))

* refactor: fix wrong modified_url debug logs ([`23d64da`](https://github.com/alandtse/auth_capture_proxy/commit/23d64da420b5326b15e1fba4e7346ed7110fbd36))

### Testing

* test: add more tests ([`7a71e9c`](https://github.com/alandtse/auth_capture_proxy/commit/7a71e9ce1ba42385957826ae031db2d01778bf01))


## v0.4.0 (2021-02-13)

### Bug Fixes

* fix: show 0 as smallest timer ([`1277c88`](https://github.com/alandtse/auth_capture_proxy/commit/1277c883e1f41e9e435813b35cef440a1e4ab2a9))

* fix: call reset_data ([`dfc6ba9`](https://github.com/alandtse/auth_capture_proxy/commit/dfc6ba9c41719175882363f0189bf3703f3c404e))

* fix: fix attribute error when not partial function ([`304f833`](https://github.com/alandtse/auth_capture_proxy/commit/304f833e830de3dcfc7dc950138af40fee5eb408))

* fix: allow successful test to return html ([`b1f20df`](https://github.com/alandtse/auth_capture_proxy/commit/b1f20df6fc0f44a5c9bc2891cca0c2edd3c09361))

* fix: treat only get to starting url as start ([`4f64265`](https://github.com/alandtse/auth_capture_proxy/commit/4f642651ec32adac7185385a42bae976e9447c16))

* fix: handle http request downgrade
NGINX reverse proxies may be providing https and all requests will
appear as http. This will automatically upgrade to https. ([`4b795b4`](https://github.com/alandtse/auth_capture_proxy/commit/4b795b41172ca762cada03d94b312284efc0f8d8))

* fix: refresh tests and modifiers
Because tests and modifiers use partials, they should be refreshed
to catch changes such as dynamic port address. ([`e140699`](https://github.com/alandtse/auth_capture_proxy/commit/e140699ebdc22d104807ebf4127c394bfceef227))

* fix: set initial header referer to start site ([`ff3c568`](https://github.com/alandtse/auth_capture_proxy/commit/ff3c5685d9c89d3a9b7bd841870fe254a03c9bd0))

* fix: shutdown clientsession on close ([`dc6b8d1`](https://github.com/alandtse/auth_capture_proxy/commit/dc6b8d1d360fc789deaeabd610830ab3513a1341))

* fix(cli): ensure tests and modifiers have port
Because we use partials and the port is not generated until after proxy
start, we need to set the tests and modifiers after start_proxy. ([`0a57143`](https://github.com/alandtse/auth_capture_proxy/commit/0a57143e1b750817d934fa7892448c02b4e0fc96))

### Build System

* build: show mypy error codes ([`0ac05ff`](https://github.com/alandtse/auth_capture_proxy/commit/0ac05ff7b475244c98bfcce833d6ae8efa6ade91))

* build(deps): remove bs4 dummy module ([`e08fdb7`](https://github.com/alandtse/auth_capture_proxy/commit/e08fdb7e1b1940a0563977498336742ae566f35d))

### Code Style

* style: fix tox errors ([`ff21e01`](https://github.com/alandtse/auth_capture_proxy/commit/ff21e011391a7df159e8a8216b73e113ce0fa302))

### Continuous Integration

* ci: add fetch depth to checkout ([`95f0bac`](https://github.com/alandtse/auth_capture_proxy/commit/95f0bacfca1077513e58dbe7f783b90176a44857))

* ci: switch to semantic-release action ([`d345ccf`](https://github.com/alandtse/auth_capture_proxy/commit/d345ccfb8a3b565d1b2959357b57c16ead736703))

### Documentation

* docs: update find_regex_url docstring ([`c15b307`](https://github.com/alandtse/auth_capture_proxy/commit/c15b30737b46f6933409341ffd9556291688e060))

* docs: update download badges ([`a8aa662`](https://github.com/alandtse/auth_capture_proxy/commit/a8aa6629c58ea00481d7a039106b2679627a083d))

### Features

* feat: add github_token to ci
Fake commit for semantic release ([`79628ca`](https://github.com/alandtse/auth_capture_proxy/commit/79628ca2aea8142bce5699d169098c474b3b6595))

* feat: dump all info from cli example ([`9d6cd3a`](https://github.com/alandtse/auth_capture_proxy/commit/9d6cd3a98d276ced9c5c6c3d5a22ecbd5caa02f2))

* feat: allow modification of headers
Modify_headers can be overriden to change behavior per site ([`2e9fc74`](https://github.com/alandtse/auth_capture_proxy/commit/2e9fc74ccfc40979747c286a1bdf6069f27e401d))

* feat: add run_func helper function ([`6d6ecd6`](https://github.com/alandtse/auth_capture_proxy/commit/6d6ecd68c988a1e3f76730971749f64c0c4408d2))

* feat: add swap_url helper ([`8ab7e9f`](https://github.com/alandtse/auth_capture_proxy/commit/8ab7e9ff5e2bc615e3e839c2006ba788058d7e37))

* feat: add prepend_url function ([`afb23bb`](https://github.com/alandtse/auth_capture_proxy/commit/afb23bb7b39b6ad2eeb2892d9ee29299138068b9))

* feat: output resp headers as json ([`bd3ba5a`](https://github.com/alandtse/auth_capture_proxy/commit/bd3ba5a7a9ce310bde64781a1d6a67e2fb53f5f9))

* feat: allow float delays for timer ([`70958da`](https://github.com/alandtse/auth_capture_proxy/commit/70958daaba3ef2542ae18dd2c1ca289b05c860d5))

* feat: allow setting of headers ([`1703d1b`](https://github.com/alandtse/auth_capture_proxy/commit/1703d1b285a330770cf355118e2ad4e43bb8ffdb))

* feat: add return_time_countdow_refresh_html
This is a helper function that can be used to add a automatic refresh
timer using javascript to a page. ([`57d71f5`](https://github.com/alandtse/auth_capture_proxy/commit/57d71f58c79ccc84324ea10808de2132199024f2))

* feat(cli): add debug option to display to stderr ([`c554e1e`](https://github.com/alandtse/auth_capture_proxy/commit/c554e1e6e228703b9042482da0e0bc3046be7013))

* feat(cli): add timeout option ([`b7eb672`](https://github.com/alandtse/auth_capture_proxy/commit/b7eb67296fe4629a664432c213f5787851ba3a99))

### Refactoring

* refactor: switch url swap to modifier ([`b515e96`](https://github.com/alandtse/auth_capture_proxy/commit/b515e96801b3837028aa1a73b5249195023b95b1))

* refactor(docs): fix spacing ([`bc0e291`](https://github.com/alandtse/auth_capture_proxy/commit/bc0e291b23fa169020e6b269a78d395a7cbdf8ba))

### Unknown

* Tesla fixes (#2)

Signed-off-by: Alan Tse <alandtse@gmail.com> ([`f6f32b4`](https://github.com/alandtse/auth_capture_proxy/commit/f6f32b4d6cf9847de76883976d0dadf13448ad86))


## v0.3.2 (2021-02-08)

### Bug Fixes

* fix: add download badge ([`0f03af4`](https://github.com/alandtse/auth_capture_proxy/commit/0f03af42883a0ef8ab0567db5eced3be9403d2cb))

* fix: handle host urls with trailing / ([`09e07f9`](https://github.com/alandtse/auth_capture_proxy/commit/09e07f9b7162e65dbf0d46369d2888e42b1a51ea))

* fix: fix issues with nginx proxy http switch ([`0ee1903`](https://github.com/alandtse/auth_capture_proxy/commit/0ee1903159a22bd269dc401e319317ee042707ef))

### Refactoring

* refactor: modify debug logs ([`dd75cbf`](https://github.com/alandtse/auth_capture_proxy/commit/dd75cbf04f9ff0b9ddaf3570647e6ae392910b94))


## v0.3.1 (2021-02-07)

### Bug Fixes

* fix: handle http downgrade by nginx proxy
Nginx appears to change the request url to http when https redirect is
enabled. This will automatically process the request as https. This
does not impact the http downgrade with start_proxy so may be a bug in
that case. ([`186dcf0`](https://github.com/alandtse/auth_capture_proxy/commit/186dcf0dded7610d7a16be2437286b61ad042599))

### Features

* feat: add option to only swap domains
Things like Referer may need to be swapped even if the proxy_url has a
path. ([`f0a6b58`](https://github.com/alandtse/auth_capture_proxy/commit/f0a6b58ababe61b009f87bb7479286ba5e22a9e1))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy into main ([`d96097c`](https://github.com/alandtse/auth_capture_proxy/commit/d96097ce5b787595baf01c7a539bf2c7095d708e))


## v0.3.0 (2021-02-07)

### Bug Fixes

* fix: handle route with variable resource
Variable resources may be pasesd into the handler as a kwarg. ([`7843953`](https://github.com/alandtse/auth_capture_proxy/commit/78439530a12a533463c892a72b1e8104cc869edf))

* fix: handle urls with or without trailing / ([`d654e52`](https://github.com/alandtse/auth_capture_proxy/commit/d654e52e29cb41922479b025b97732430131166b))

* fix: fix amazon test to recognize captcha logins ([`be092ea`](https://github.com/alandtse/auth_capture_proxy/commit/be092ea8ba6e25b944be8f74277ab7428ff8c740))

* fix: only update blank fields ([`1a83f4d`](https://github.com/alandtse/auth_capture_proxy/commit/1a83f4dd11988adcbadf8c646c8e663251a0a1f4))

### Features

* feat: add change_host_url
Allow a proxy host target to be changed. ([`fe6226e`](https://github.com/alandtse/auth_capture_proxy/commit/fe6226ee9cc9f6a1aecf6cf84e963ab6ad8470c7))

* feat: add reset_data option
Because routes may not be deleted in aiohttp, a long running server may
use the same endpoint to oauth proxy multiple accounts. This will reset
all data from a proxy session. This should be called after a succesful
login. ([`97871ef`](https://github.com/alandtse/auth_capture_proxy/commit/97871ef173fa7fe346850a4abb6814a5b3ee1d22))

* feat: allow enable/disable of all_handler
All_handler may be passed to other aiohttp web servers to handle a
route. However, this can pose a security risk because the proxy could
be used by an outside attacker to access the logged in account or as a
reflective proxy because aiohttp does not allow routes to be removed. By
disabling all_handler, the proxy can be disabled even if the route is
left open. ([`3a7c0f1`](https://github.com/alandtse/auth_capture_proxy/commit/3a7c0f111f6831ccb2d3c2210ca3ce6132a490a0))

* feat: allow coroutines for testers and modifiers ([`86da57b`](https://github.com/alandtse/auth_capture_proxy/commit/86da57b235212b97d7e50a576ad1317cdd5a3113))

### Refactoring

* refactor: lower debug level for swap_url warning ([`850a2d9`](https://github.com/alandtse/auth_capture_proxy/commit/850a2d934753a3549c7791eab6a6dcfb1649ae36))

* refactor: fix lint errors ([`b21898c`](https://github.com/alandtse/auth_capture_proxy/commit/b21898c9e3d16c52789fc2f2c8e6c203b87535c6))


## v0.2.0 (2021-02-06)

### Bug Fixes

* fix: fix TypeError in autofill ([`160eb48`](https://github.com/alandtse/auth_capture_proxy/commit/160eb48fd9be00f907235359860b6771811fcb0f))

### Documentation

* docs: add sections to readme ([`a152d52`](https://github.com/alandtse/auth_capture_proxy/commit/a152d5251747572f2a59076f4e00850b3236e892))

### Features

* feat: add modifiers to cli example ([`eae4030`](https://github.com/alandtse/auth_capture_proxy/commit/eae4030ba4f47468563e1abdaa186ed221eeb42d))

### Unknown

* Merge branch 'main' of https://github.com/alandtse/auth_capture_proxy into main ([`d8d9ed1`](https://github.com/alandtse/auth_capture_proxy/commit/d8d9ed15169c7c37301ea56b276e1a98b6cc2c23))


## v0.1.2 (2021-02-05)

### Bug Fixes

* fix: capture toomanyredirects error ([`f515818`](https://github.com/alandtse/auth_capture_proxy/commit/f515818860e0ed6484c6d90aed70c60671f53177))

* fix: require python 3.6.1 to satisfy deps ([`ad948df`](https://github.com/alandtse/auth_capture_proxy/commit/ad948dff71de2ccd1d0555e129db07aeeb7fa890))

* fix: add support for python3.6 ([`adf6ff6`](https://github.com/alandtse/auth_capture_proxy/commit/adf6ff649681397dad3c1b4aff72b6f493803b85))

### Continuous Integration

* ci: add token to checkout action ([`532e738`](https://github.com/alandtse/auth_capture_proxy/commit/532e738a9118bb6616525e6d712c37e2f4016eba))

### Documentation

* docs: change changelog to semantic-release ([`c015d51`](https://github.com/alandtse/auth_capture_proxy/commit/c015d514896f0e6091cd10cc10903d17b7185921))

### Features

* feat: add proxy-example to cli
This is also a good starter example. ([`85c2d1e`](https://github.com/alandtse/auth_capture_proxy/commit/85c2d1ec28de648f535ac5c7267ebcd27e74cdca))


## v0.1.1 (2021-02-04)

### Bug Fixes

* fix: add support for python 3.7 ([`95a7d33`](https://github.com/alandtse/auth_capture_proxy/commit/95a7d33e3d32ea6447be157c66fc9e130ae0e4e2))

### Continuous Integration

* ci: add coveralls repo token ([`06f4369`](https://github.com/alandtse/auth_capture_proxy/commit/06f4369a2b76d565d0c7561536a7b920c2419b32))

* ci: add gitub token for coveralls ([`031cf27`](https://github.com/alandtse/auth_capture_proxy/commit/031cf27ac64fb0f0526d4166713587bf1c888775))

* ci: switch back to pip coveralls ([`7d725b8`](https://github.com/alandtse/auth_capture_proxy/commit/7d725b882b134260f83eed54f2ff931cb874716c))

* ci: change to with for coveralls token ([`c8c5363`](https://github.com/alandtse/auth_capture_proxy/commit/c8c53634c623d419722d991af03d7c9319d42170))

* ci: add github_token for coveralls ([`87fe69f`](https://github.com/alandtse/auth_capture_proxy/commit/87fe69f8bdd0fadb20c13ef91359611ab78b6226))

* ci: use githubaction for coveralls ([`7d5a4ed`](https://github.com/alandtse/auth_capture_proxy/commit/7d5a4ed5a85d56a55adc0851b87b76fdaa51225b))

### Documentation

* docs: cleanup spacing ([`73b0ba6`](https://github.com/alandtse/auth_capture_proxy/commit/73b0ba69aed1bcdf2230755ef35d8fe85592f1ed))

* docs: simplify publishing instructions ([`30f1ec2`](https://github.com/alandtse/auth_capture_proxy/commit/30f1ec27315fea8915566583ffaf341d9c6aeb01))

* docs: fix readthdocs shield ([`004596d`](https://github.com/alandtse/auth_capture_proxy/commit/004596dae5cc4b8bbec7f4f31aa259767b990bd7))

* docs: fix pypi shield link ([`2389ea3`](https://github.com/alandtse/auth_capture_proxy/commit/2389ea358d0500693b5cdf2dcf6b6652e784cf49))

* docs: fix pypi links ([`1676058`](https://github.com/alandtse/auth_capture_proxy/commit/167605840e4a1cf4689025cc3106fa42dad01bcd))

* docs: fix broken shields and links ([`902b83e`](https://github.com/alandtse/auth_capture_proxy/commit/902b83ec48173d2a67e94740e824719a5f4de102))


## v0.1.0 (2021-02-04)

### Continuous Integration

* ci: fix release errors ([`6d5511b`](https://github.com/alandtse/auth_capture_proxy/commit/6d5511b967e92d965f97d39f6272dceb7128ff7d))

* ci: add release on push ([`0561ca6`](https://github.com/alandtse/auth_capture_proxy/commit/0561ca6ece10aa0307add9634cbbaa2355da8506))

### Features

* feat: initial commit ([`32a20f0`](https://github.com/alandtse/auth_capture_proxy/commit/32a20f00bdddabbf1eac5e22d1d00b2c281dd940))
