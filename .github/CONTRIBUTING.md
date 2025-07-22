# Contributing to Völva

Thank you for considering contributing to Völva! Before you start, please ensure you've read our [License](../LICENSE.md) and [Code of Conduct](../CODE_OF_CONDUCT.md).

## Development Environment

- **IDE**: Visual Studio Code  
- **Python**: Version `3.13.1` (via `venv`)  
- **Linting**: `flake8`, `flake8-docstrings`  
- **Formatting**: `autopep8`  
- **Testing**: `pytest`  
- **CI/CD**: GitHub Actions  

>  Do **not** use global Python installations. Use a virtual environment (`venv`) to avoid breaking system packages, especially on Debian.

## How to Contribute

1. **Fork and Clone**  
   Fork this repository to your account and clone it locally.

2. **Create a Feature Branch**  
   Use the format mentioned in _Branching Strategy_ chapter below.

3. **Make Your Changes**  
   See `.PULL_REQUEST_TEMPLATE`

4. **Test and Check Quality**  
   - Run `pytest` locally and fix all failing tests.  
   - Use `pre-commit` to automatically format and lint your code.

5. **Submit a Pull Request (PR)**  
   - Clearly explain what the PR does and reference the related issue (`Fixes #42`) when applicable.  
   - Enable “Allow edits by maintainers”.  

## Branching Strategy

Note that the `release` branch follows the versioning mentioned in _Versioning & Release Notes_ chapter below.

| Branch Type   | Pattern        | Base     | Purpose                                                | Code Review? |   PR?    |
| ------------- | -------------- | -------- | ------------------------------------------------------ | ------------ | -------- |
| Stable        | `main`         | `release` | Production-ready. Accepts only `release` and `hotfix`. |   Yes       |    Yes   |
| Release       | `release/v#-*` |  `dev`   | Final preparations for a stable release.               |    Yes       |    Yes   |
| Hotfix        | `hotfix/#/*`   |  `main`  | Emergency fix for production.                          |    Yes       |    Yes   |
| Development   | `dev`          |  –       | Main development branch.                               |    No        |    Yes   |

### Developers Branches 

Development happens on these branches, followed by the patterns `type/#/description`, for example: `feature/108/fix-input-validation`.

It's main development branch (the "main") is the ´dev´ branch. 

| Branch Type   | Pattern        | Base     | Purpose                                                | Review / PR? |
| ------------- | -------------- | -------- | ------------------------------------------------------ | ------------ |
| Feature       | `feature/#/*`  |  `dev`    | Adds new features.                                    |      No      |
| Enhancement   | `enhancement/#/*`   |  `dev`    | Code enhanced.                                   |      No      |
| Bugfix        | `bugfix/#/*`   |  `dev`    | Fixes known bugs.                                     |      No      |
| Documentation | `docs/*`       |  `dev`    | Docs only—no code changes.                            |      No      |


## Versioning & Release Notes

All merges into `main` must include a proper changelog entry (see [CHANGELOG guidelines](https://gist.github.com/juampynr/4c18214a8eb554084e21d6e288a18a2c)).

We follow [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`

- **Major**: Breaking changes, significant architecture shifts  
- **Minor**: New features, major bug fixes  
- **Patch**: Minor fixes, documentation, or cleanup

Example: `v1.2.3-beta`.


## How to Cite This Project

To cite the Völva system in academic or research work, please use the format below, or refer to the `CITATION.cff` file located at the root of the repository:

```yaml
cff-version: 1.2.0
title: Völva
authors:
  - family-names: 
    given-names: 
  - family-names: 
    given-names: 
version: 1.0.0
date-released: 2025-05-15
repository-code: https://github.com/volvan
license: custom
message: "If you use Völva in academic work, please cite it using this metadata."
```

For more on how to format citations for software, see:  
[https://citation-file-format.github.io](https://citation-file-format.github.io)

---

If you have any questions or ideas, please open an issue or reach us at **[volva@frostbyte.is](mailto:volva@frostbyte.is)**.

Thank you for contributing to a safer, more transparent Internet!
