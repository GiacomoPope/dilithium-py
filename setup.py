from setuptools import setup

setup(
    name="dilithium-py",
    version="1.0.2",
    python_requires=">=3.9",
    description="A pure python implementation of ML-DSA (FIPS 204)",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
    ],
    license="MIT",
    url="https://github.com/GiacomoPope/dilithium-py",
    install_requires=["pycryptodome", "xoflib"],
)
