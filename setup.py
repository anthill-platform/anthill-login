
from setuptools import setup, find_namespace_packages

DEPENDENCIES = [
    "anthill-common>=0.2.5"
]

setup(
    name='anthill-login',
    package_data={
      "anthill.login": ["anthill/login/sql", "anthill/login/static", "anthill/login/template"]
    },
    version='0.2',
    description='An authentication service for Anthill platform',
    author='desertkun',
    license='MIT',
    author_email='desertkun@gmail.com',
    url='https://github.com/anthill-platform/anthill-login',
    namespace_packages=["anthill"],
    include_package_data=True,
    packages=find_namespace_packages(include=["anthill.*"]),
    zip_safe=False,
    install_requires=DEPENDENCIES
)
