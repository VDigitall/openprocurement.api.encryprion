from setuptools import setup, find_packages
import os

version = '1.0'

requires = [
    'setuptools',
    'pyramid',
    'libnacl',
]

test_requires = requires + [
    'webtest',
    'python-coveralls',
]

entry_points = {
    'paste.app_factory': [
        'main = openprocurement.api.encryprion:main'
    ],
    'console_scripts': [
        'encrypt_data_bridge = openprocurement.api.encryprion.databridge:main'
    ]
}

setup(name='openprocurement.api.encryprion',
      version=version,
      description="",
      long_description=open("README.rst").read(),
      # Get more strings from
      # http://pypi.python.org/pypi?:action=list_classifiers
      classifiers=[
        "Programming Language :: Python",
      ],
      keywords='',
      author='Quintagroup, Ltd.',
      author_email='info@quintagroup.com',
      url='http://svn.plone.org/svn/collective/',
      license='Apache License 2.0',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['openprocurement', 'openprocurement.api'],
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=test_requires,
      extras_require={'test': test_requires},
      entry_points=entry_points)
