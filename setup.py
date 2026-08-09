from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="bugforge",
    version="1.0.0",
    description="A modular, dependency-light bug bounty toolkit (recon, vuln helpers, scope validation, reports)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="BugForge Contributors",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[],  # zero runtime deps — stdlib only
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov"],
    },
    entry_points={
        "console_scripts": [
            "bugforge=bugforge.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    keywords="bug bounty, security, pentesting, recon, xss, ssrf, sqli, idor, cors, cvss",
)
