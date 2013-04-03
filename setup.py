import os

from setuptools import setup, find_packages


setup(
    name='akanda-nova',
    version='0.1.1',
    description='OpenStack L3 User-Facing REST API for Nova',
    author='DreamHost',
    author_email='dev-community@dreamhost.com',
    url='http://github.com/dreamhost/akanda',
    license='BSD',
    install_requires=[
    ],
    namespace_packages=['akanda'],
    packages=find_packages(exclude=['test', 'smoke']),
    include_package_data=True,
    zip_safe=False,
)
