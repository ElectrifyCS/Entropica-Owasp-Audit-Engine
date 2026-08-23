from setuptools import setup, find_packages

setup(
    name="entropica_audit_engine",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.27",
        "fastapi>=0.110",
        "uvicorn>=0.29",
    ],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
)
