from setuptools import setup


version = '0.0.3'


install_requires = ['cffi>=1.14']
setup_requirements = ['setuptools'] + install_requires
tests_require = ['pytest==6.2.4', 'hypothesis==6.14.1', 'pytest-cov==2.12.1']
docs_require  = ['Sphinx>=3.*']


setup(
    name='monocypher-py',
    version=version,

    description='Python binding to the Monocypher library',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/eugene-eeo/monocypher-py',
    license='CC0 1.0 Universal',

    author='Eeo Jun',
    author_email='141bytes@gmail.com',
    python_requires='>=3.6',
    setup_requires=setup_requirements,
    install_requires=install_requires,
    extras_require={
        'tests': tests_require,
        'docs':  docs_require,
    },
    tests_require=tests_require,

    package_dir={"": "src"},
    packages=[
        "monocypher",
        "monocypher.bindings",
    ],

    # CFFI
    ext_package="monocypher",
    cffi_modules=["src/build.py:ffi"],
    zip_safe=False,
)
