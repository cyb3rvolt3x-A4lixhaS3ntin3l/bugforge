# Contributing to Gungnir

Thanks for your interest in improving Gungnir! Security tooling thrives on community contributions — new payloads, detection signatures, and report templates are all incredibly valuable.

## Ways to contribute

- **Add payload sets** — new XSS/SSRF/SQLi payloads, especially WAF-bypass variants
- **Add detection signatures** — secret patterns, SQL error fingerprints, tech markers
- **Improve report templates** — clearer impact language, new bug-class templates
- **Add recon sources** — new passive subdomain or content-discovery sources
- **Fix bugs** — see [issues](../../issues)
- **Improve docs** — examples, guides, translations

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/gungnir.git
cd gungnir
pip install -e ".[dev]"
pytest -q
```

## Guidelines

1. **Keep it dependency-light.** The zero-runtime-dependency principle is a feature. Avoid adding packages unless absolutely necessary. Use the standard library.
2. **Write tests.** New logic needs tests in `tests/`. Run `pytest` before pushing.
3. **Type hints.** All public functions should be type-annotated.
4. **Responsibility.** Never add functionality designed for out-of-scope or destructive testing. Gungnir is for authorized, responsible testing only.
5. **Commit style.** Use clear, conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.

## Pull request process

1. Fork the repo and create a feature branch from `main`
2. Write your code + tests
3. Ensure `pytest` passes and `python -m gungnir --help` works
4. Update README/docs if you add a feature
5. Open a PR describing the change and why it's useful

## Code of Conduct

Be respectful and professional. Harassment of any kind will not be tolerated.
