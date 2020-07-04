from setuptools import setup


version = '0.0.1'


install_requires = ['cffi>=1.14.0']
setup_requirements = ['setuptools'] + install_requires
tests_require = ['pytest>=5.4.3', 'hypothesis>=5.16.1', 'pytest-cov>=2.10.0']
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
    python_requires='>=3.5',
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
