
from setuptools import setup, find_packages

DEPENDENCIES = [
    "anthill-common>=0.1.0"
]

setup(
    name='anthill-login',
    version='0.1.0',
    description='An authentication service for Anthill platform',
    author='desertkun',
    license='MIT',
    author_email='desertkun@gmail.com',
    url='https://github.com/anthill-platform/anthill-login',
    namespace_packages=["anthill"],
    include_package_data=True,
    package_data={
      "anthill.login": ["anthill/login/sql", "anthill/login/static"]
    },
    packages=find_packages(),
    zip_safe=False,
    install_requires=DEPENDENCIES
)
