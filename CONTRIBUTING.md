# Contributing

Auth_capture_proxy is licensed under the [Apache License 2.0](https://spdx.org/licenses/Apache-2.0.html).
[New issues](https://github.com/alandtse/auth_capture_proxy/issues) and pull requests are welcome.
Feel free to [ask a question](https://github.com/alandtse/auth_capture_proxy/issues/new?assignees=&labels=kind%3A+question&template=question.md).
Contributors are asked to abide by both the [GitHub community guidelines](https://docs.github.com/en/github/site-policy/github-community-guidelines)
and the [Contributor Code of Conduct, version 2.0](https://github.com/alandtse/auth_capture_proxy/blob/main/CODE_OF_CONDUCT.md).

#### Pull requests

If you can, update `CHANGELOG.md` and add your name to the contributors in `pyproject.toml`
so that you’re credited. Run `tyrannosaurus sync` to sync metadata.

#### Publishing a new version

1. Bump the version in `tool.poetry.version` in `pyproject.toml`, following
   [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
2. Run `tyrannosaurus sync` so that the Poetry lock file is up-to-date
   and metadata are synced to pyproject.toml.
3. Create a [new release](https://github.com/dmyersturnbull/tyrannosaurus/releases/new)
   with both the name and tag set to something like `v1.4.13` (keep the _v_).
4. An hour later, check that the _publish on release creation_
   [workflow](https://github.com/alandtse/auth_capture_proxy/actions) passes
   and that the PyPi, Docker Hub, and GitHub Package versions are updated as shown in the
   shields on the readme.
5. Check for a pull request from regro-cf-autotick-bot on the
   [feedstock](https://github.com/conda-forge/auth_capture_proxy-feedstock).
   _If you have not changed the dependencies or version ranges_, go ahead and merge it.
   Otherwise, [update the recipe](https://github.com/conda-forge/auth_capture_proxy-feedstock/edit/master/recipe/meta.yaml)
   with those changes under `run:`, also updating `{% set version` and `sha256` with the
   changes from regro-cf-autotick-bot. You can alternatively re-run `tyrannosaurus recipe`
   to generate a new recipe and copy it to the feedstock.
6. Twenty minutes later, verify that the Conda-Forge shield is updated.
