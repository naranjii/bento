from setuptools import setup, find_packages

setup(
    name='bento',
    version='0.1.0',
    description='A CLI for VirusTotal API v2.0',
    author='naranjii',
    packages=find_packages(),
    install_requires=[
        'requests',
        'click',
    ],
    entry_points={
        'console_scripts': [
            'bento=bento.cli:main',
        ],
    },
    python_requires='>=3.7',
)
