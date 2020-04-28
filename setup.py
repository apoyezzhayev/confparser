from setuptools import setup, find_namespace_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='confparser',
    # Versions should comply with PEP 440
    version='0.0.1',

    description='Configuration parser',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        'PyYAML',
    ],
    url='',  # Optional

    author='apoyezzhaev',
    author_email='arseniy.poyezzhayev@gmail.com',
    license='MIT'
)
