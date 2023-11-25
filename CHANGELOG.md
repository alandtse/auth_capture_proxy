# Changelog for auth_capture_proxy

<!--next-version-placeholder-->

## v1.2.1 (2023-11-25)

### Fix

* Fix multiple / detection in urls ([`2352e22`](https://github.com/alandtse/auth_capture_proxy/commit/2352e22cabcf9c5fb39499f588026bac2462d18d))

## v1.2.0 (2023-05-08)
### Feature
* Require python 3.10 ([`9ede8e1`](https://github.com/alandtse/auth_capture_proxy/commit/9ede8e1961d9cd3ee188bd8145810c1003a004a3))

## v1.1.6 (2023-05-08)
### Fix
* Require python 3.9 or greater ([`5ba1afd`](https://github.com/alandtse/auth_capture_proxy/commit/5ba1afdaf2cbdf16a82c7f40d2d56d145b8b369f))

## v1.1.5 (2023-05-07)
### Fix
* **access_url:** Do not add port if 0 ([`ba9acb4`](https://github.com/alandtse/auth_capture_proxy/commit/ba9acb49f106a76c32f95ef3ef871444309597e0))

## v1.1.4 (2022-06-25)
### Fix
* Fix swap_url for http converted urls ([`2b672fa`](https://github.com/alandtse/auth_capture_proxy/commit/2b672fa3a9c86ecf4dd64d7fc7d66a8a7fa1d5ff))

## v1.1.3 (2022-02-25)
### Fix
* Bump multidict ([`bf8c7c1`](https://github.com/alandtse/auth_capture_proxy/commit/bf8c7c13252d2042f07a8ad2de1e6aba188e6985))

## v1.1.2 (2022-02-25)
### Fix
* Bump dependencies ([#19](https://github.com/alandtse/auth_capture_proxy/issues/19)) ([`76c9344`](https://github.com/alandtse/auth_capture_proxy/commit/76c9344d656bcff61996fb335b94ecf9c3b35804))

## v1.1.1 (2021-11-23)
### Fix
* Enable redirect following ([#18](https://github.com/alandtse/auth_capture_proxy/issues/18)) ([`0f011ac`](https://github.com/alandtse/auth_capture_proxy/commit/0f011accbb50412a54a9ca0a853cceb5a88a3ce6))

## v1.1.0 (2021-11-23)
### Feature
* Bump for release ([`9ff7b15`](https://github.com/alandtse/auth_capture_proxy/commit/9ff7b159e91902801345b95a0d9cdcf24e5a8d04))

## v1.0.2 (2021-08-10)
### Fix
* Fix multiple cookie error in debug ([#17](https://github.com/alandtse/auth_capture_proxy/issues/17)) ([`f1cd671`](https://github.com/alandtse/auth_capture_proxy/commit/f1cd671b63dd495b2c90aefd51c59a8fbc004cae))

## v1.0.1 (2021-05-01)
### Fix
* Relax dependency versions ([`55c12ce`](https://github.com/alandtse/auth_capture_proxy/commit/55c12ce0ac96d232e1790824360d745ecbf27163))

## v1.0.0 (2021-04-27)
### Fix
* Swap to httpx ([#13](https://github.com/alandtse/auth_capture_proxy/issues/13)) ([`311e998`](https://github.com/alandtse/auth_capture_proxy/commit/311e998b287dc445d002e5e1aceebe17e82adb65))

### Breaking
* API has changed due to use of httpx. Modifiers, test_url, and other items that access aiohttp ClientResponse will need to be fixed.  ([`311e998`](https://github.com/alandtse/auth_capture_proxy/commit/311e998b287dc445d002e5e1aceebe17e82adb65))

## v0.8.1 (2021-04-03)
### Fix
* Export const ([#12](https://github.com/alandtse/auth_capture_proxy/issues/12)) ([`afc6b7c`](https://github.com/alandtse/auth_capture_proxy/commit/afc6b7c50dcaca8e8ff3811672ce8610c376974a))

## v0.8.0 (2021-04-03)
### Feature
* Allow disabling of header autogeneration ([#11](https://github.com/alandtse/auth_capture_proxy/issues/11)) ([`3eade2d`](https://github.com/alandtse/auth_capture_proxy/commit/3eade2deedf82c96bbf90724f5eee8c8a8a70234))

## v0.7.1 (2021-03-29)
### Fix
* Fix filter on redirect detection ([#10](https://github.com/alandtse/auth_capture_proxy/issues/10)) ([`94fb40e`](https://github.com/alandtse/auth_capture_proxy/commit/94fb40e81b7a1cdb5c6cc85bad1d68c4802d9ff6))

## v0.7.0 (2021-03-13)
### Feature
* Add filter for check_redirects ([#6](https://github.com/alandtse/auth_capture_proxy/issues/6)) ([`144147a`](https://github.com/alandtse/auth_capture_proxy/commit/144147a365293541a763d4a8957b57d1ed2c7aaa))

## v0.6.0 (2021-03-01)
### Feature
* Change host when redirect detected ([`1d6fa10`](https://github.com/alandtse/auth_capture_proxy/commit/1d6fa10085a0f7ccd049caa2a0d3778c12a276fc))

## v0.5.0 (2021-02-25)
### Feature
* Process multipart/form-data ([#4](https://github.com/alandtse/auth_capture_proxy/issues/4)) ([`d9fc558`](https://github.com/alandtse/auth_capture_proxy/commit/d9fc558347df82f45330a76c04969d3e99b25717))

## v0.4.2 (2021-02-20)
### Fix
* Bump dependencies ([`6e9dfd8`](https://github.com/alandtse/auth_capture_proxy/commit/6e9dfd89a059c3c272ad2be0ec4da3f6f439a0ce))

## v0.4.1 (2021-02-13)
### Fix
* Expose prepend and swap_url ([`2ea2b16`](https://github.com/alandtse/auth_capture_proxy/commit/2ea2b16f07bbf15926de06efb56b15393f9d9196))

## v0.4.0 (2021-02-13)

### Feature

- Add github_token to ci ([`79628ca`](https://github.com/alandtse/auth_capture_proxy/commit/79628ca2aea8142bce5699d169098c474b3b6595))
- Dump all info from cli example ([`9d6cd3a`](https://github.com/alandtse/auth_capture_proxy/commit/9d6cd3a98d276ced9c5c6c3d5a22ecbd5caa02f2))
- Allow modification of headers ([`2e9fc74`](https://github.com/alandtse/auth_capture_proxy/commit/2e9fc74ccfc40979747c286a1bdf6069f27e401d))
- Add run_func helper function ([`6d6ecd6`](https://github.com/alandtse/auth_capture_proxy/commit/6d6ecd68c988a1e3f76730971749f64c0c4408d2))
- Add swap_url helper ([`8ab7e9f`](https://github.com/alandtse/auth_capture_proxy/commit/8ab7e9ff5e2bc615e3e839c2006ba788058d7e37))
- Add prepend_url function ([`afb23bb`](https://github.com/alandtse/auth_capture_proxy/commit/afb23bb7b39b6ad2eeb2892d9ee29299138068b9))
- Output resp headers as json ([`bd3ba5a`](https://github.com/alandtse/auth_capture_proxy/commit/bd3ba5a7a9ce310bde64781a1d6a67e2fb53f5f9))
- Allow float delays for timer ([`70958da`](https://github.com/alandtse/auth_capture_proxy/commit/70958daaba3ef2542ae18dd2c1ca289b05c860d5))
- Allow setting of headers ([`1703d1b`](https://github.com/alandtse/auth_capture_proxy/commit/1703d1b285a330770cf355118e2ad4e43bb8ffdb))
- Add return_time_countdow_refresh_html ([`57d71f5`](https://github.com/alandtse/auth_capture_proxy/commit/57d71f58c79ccc84324ea10808de2132199024f2))
- **cli:** Add debug option to display to stderr ([`c554e1e`](https://github.com/alandtse/auth_capture_proxy/commit/c554e1e6e228703b9042482da0e0bc3046be7013))
- **cli:** Add timeout option ([`b7eb672`](https://github.com/alandtse/auth_capture_proxy/commit/b7eb67296fe4629a664432c213f5787851ba3a99))

### Fix

- Show 0 as smallest timer ([`1277c88`](https://github.com/alandtse/auth_capture_proxy/commit/1277c883e1f41e9e435813b35cef440a1e4ab2a9))
- Call reset_data ([`dfc6ba9`](https://github.com/alandtse/auth_capture_proxy/commit/dfc6ba9c41719175882363f0189bf3703f3c404e))
- Fix attribute error when not partial function ([`304f833`](https://github.com/alandtse/auth_capture_proxy/commit/304f833e830de3dcfc7dc950138af40fee5eb408))
- Allow successful test to return html ([`b1f20df`](https://github.com/alandtse/auth_capture_proxy/commit/b1f20df6fc0f44a5c9bc2891cca0c2edd3c09361))
- Treat only get to starting url as start ([`4f64265`](https://github.com/alandtse/auth_capture_proxy/commit/4f642651ec32adac7185385a42bae976e9447c16))
- Handle http request downgrade ([`4b795b4`](https://github.com/alandtse/auth_capture_proxy/commit/4b795b41172ca762cada03d94b312284efc0f8d8))
- Refresh tests and modifiers ([`e140699`](https://github.com/alandtse/auth_capture_proxy/commit/e140699ebdc22d104807ebf4127c394bfceef227))
- Set initial header referer to start site ([`ff3c568`](https://github.com/alandtse/auth_capture_proxy/commit/ff3c5685d9c89d3a9b7bd841870fe254a03c9bd0))
- Shutdown clientsession on close ([`dc6b8d1`](https://github.com/alandtse/auth_capture_proxy/commit/dc6b8d1d360fc789deaeabd610830ab3513a1341))
- **cli:** Ensure tests and modifiers have port ([`0a57143`](https://github.com/alandtse/auth_capture_proxy/commit/0a57143e1b750817d934fa7892448c02b4e0fc96))

### Documentation

- Update find_regex_url docstring ([`c15b307`](https://github.com/alandtse/auth_capture_proxy/commit/c15b30737b46f6933409341ffd9556291688e060))
- Update download badges ([`a8aa662`](https://github.com/alandtse/auth_capture_proxy/commit/a8aa6629c58ea00481d7a039106b2679627a083d))

### Refactor

- Switch url swap to modifier ([`b515e96`](https://github.com/alandtse/auth_capture_proxy/commit/b515e96801b3837028aa1a73b5249195023b95b1))
- **docs:** Fix spacing ([`bc0e291`](https://github.com/alandtse/auth_capture_proxy/commit/bc0e291b23fa169020e6b269a78d395a7cbdf8ba))

## v0.3.2 (2021-02-08)

### Fix

- Add download badge ([`0f03af4`](https://github.com/alandtse/auth_capture_proxy/commit/0f03af42883a0ef8ab0567db5eced3be9403d2cb))

## v0.3.1 (2021-02-07)

### Fix

- Handle http downgrade by nginx proxy ([`186dcf0`](https://github.com/alandtse/auth_capture_proxy/commit/186dcf0dded7610d7a16be2437286b61ad042599))

## v0.3.0 (2021-02-07)

### Feature

- Add change_host_url ([`fe6226e`](https://github.com/alandtse/auth_capture_proxy/commit/fe6226ee9cc9f6a1aecf6cf84e963ab6ad8470c7))

## v0.2.0 (2021-02-06)

### Feature

- Add modifiers to cli example ([`eae4030`](https://github.com/alandtse/auth_capture_proxy/commit/eae4030ba4f47468563e1abdaa186ed221eeb42d))

## v0.1.2 (2021-02-05)

### Fix

- Require python 3.6.1 to satisfy deps ([`ad948df`](https://github.com/alandtse/auth_capture_proxy/commit/ad948dff71de2ccd1d0555e129db07aeeb7fa890))

## v0.1.2 (2021-02-04)

### Fix

- Add support for python 3.7 (95a7d33e3d32ea6447be157c66fc9e130ae0e4e2)

## v0.1.1 (2021-02-04)

### Feat

- Initial release
