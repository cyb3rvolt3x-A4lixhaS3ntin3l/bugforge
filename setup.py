from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="bugforge",
    version="2.0.0",
    description="Bug bounty orchestration platform — web UI, tool orchestration, pipeline engine, recon, vulns, reports",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="BugForge Contributors",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "pydantic>=2.0.0",
        "websockets>=12.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-asyncio>=0.23.0", "httpx"],
    },
    entry_points={
        "console_scripts": [
            "bugforge=bugforge.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    keywords="bug bounty, security, pentesting, recon, orchestration, subfinder, nuclei, ffuf, dalfox, sqlmap",
)
