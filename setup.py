

from setuptools import setup

setup(name='py42query',
      version='0.2',
      description='Query, prepare, and load Code42 data for analysis.',
      url='https://stash.corp.code42.com/projects/PI/repos/py42query/',
      author='Matt Parker',
      author_email='matt.parker@code42.com',
      license='Internal use only',
      py_modules=['py42query'],
      install_requires=[
          'requests',
          'boto3',
          'structlog',
          'joblib'],
      zip_safe=False)
