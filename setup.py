from setuptools import setup

setup(
    name='otree_repository',
    packages=['otree_repository'],
    include_package_data=True,
    install_requires=[
        'flask',
        'flask-security',
        'flask-sqlalchemy',
        'pyclamd'
    ],
)