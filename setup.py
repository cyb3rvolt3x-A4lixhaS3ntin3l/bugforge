from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="gungnir-security",
    version="4.0.0",
    description="GUNGNIR — Parallel bug bounty intelligence platform with 8 native modules, 26 attack chain patterns, custom pipelines, finding lifecycle, and web UI. By Syed Zada Abrar (Andrax Pentester).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Syed Zada Abrar",
    author_email="andraxpentester@gmail.com",
    url="https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "pydantic>=2.0.0",
        "websockets>=12.0",
        "pyyaml>=6.0",
        "bcrypt>=4.0.0",
        "itsdangerous>=2.0.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-asyncio>=0.23.0", "httpx"],
    },
    entry_points={
        "console_scripts": [
            "gungnir=gungnir.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords=[
        "gungnir", "bug bounty", "bugbounty", "security", "pentesting",
        "penetration testing", "ethical hacking", "recon", "reconnaissance",
        "vulnerability scanner", "subdomain enumeration", "xss", "ssrf", "sqli",
        "nuclei", "subfinder", "ffuf", "dalfox", "sqlmap", "gitleaks",
        "attack surface", "cybersecurity", "security automation",
        "bug bounty tools", "security tools", "vulnerability assessment",
        "web application security", "API security", "OWASP",
        "Syed Zada Abrar", "Andrax Pentester", "Cyb3rVolt3x",
        "andraxpentester", "sentinelreign",
    ],
)
