# GitHub Actions workflows

| Workflow | Runs on | Secrets | What it does |
|---|---|---|---|
| `tests.yml` | push, pull request (all branches), manual | none | flake8 (syntax errors only), pytest with coverage on Python 3.12 and 3.13, Bandit. |
| `sonar.yml` | push, pull request, manual | `SONAR_TOKEN` | Runs the tests with coverage, then SonarCloud analysis. Fails early with a clear message if `SONAR_TOKEN` is missing. |
| `gitleaks.yml` | push, manual | none | Gitleaks secret scan of the full history with `gitleaks/gitleaks.toml`; report uploaded as an artifact (non-blocking). |
| `dependencycheck.yml` | push, manual | none | OWASP Dependency-Check (SCA); HTML report uploaded as an artifact. |

## One-time setup

1. SonarCloud: in the organization `niscy-eudiw`, create the project with key
   `niscy-eudiw_pyMDOC-CBOR` (the workflow derives it as `<owner>_<repo>`).
   Under Administration > Analysis Method, turn **Automatic Analysis off**:
   the workflow runs a CI analysis with coverage, and SonarCloud rejects CI
   analyses while Automatic Analysis is on.
2. Repository secrets (Settings > Secrets and variables > Actions):
   - `SONAR_TOKEN`: a SonarCloud token (My Account > Security) for the project above.

`tests.yml`, `gitleaks.yml`, `dependencycheck.yml` need no secrets. `GITHUB_TOKEN` is provided by GitHub automatically.
