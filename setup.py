#####################################################
# Author: Laszlo Popovics                           #
# Version: 1.0                                      #
# Program: AIOneGuardChain Storeage cell - Setup    #
#####################################################

from setuptools import setup, find_namespace_packages
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aioneguard",
    version="1.0.0.0",
    description="AIOneGuardChain Storage Cell - The BlockChain Object Storage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Laszlo Popovics",
    author_email="laszlo@aivantguard.com",
    url="https://github.com/aivantguardchain_store",
    packages=find_namespace_packages(include=["aioneguard.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        'fastapi', 'uvicorn', 'pydantic', 'starlette', 'jinja2', 'websockets', 'requests', 'pytz',
        'boto3', 'pycryptodome', 'cryptography', 'pynacl', 'liboqs-python', 'argon2-cffi'
    ],
    license="Proprietary",
    license_files=["LICENSE"],
    include_package_data=True,
)
