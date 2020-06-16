from distutils.core import setup


version = '0.0.1'


setup_requirements = ['setuptools', 'cffi>=1.14.0']
tests_require = ['pytest>=5.4.3', 'hypothesis>=5.16.1']


setup(
    name='monocypher-py',
    version=version,

    description='Python binding to the Monocypher library',
    long_description=open('README.md', 'r').read(),
    url='https://github.com/eugene-eeo/monocypher-py',
    license='CC0 1.0 Universal',

    author='Eeo Jun',
    author_email='141bytes@gmail.com',
    python_requires='>=3.5',
    setup_requirements=setup_requirements,
    extras_require={
        'tests': tests_require,
    },
    tests_require=tests_require,

    package_dir={"": "src"},
    packages=[
        "monocypher",
        "monocypher.utils",
    ],
    # ext_package="monocypher._monocypher",
    cffi_modules=["src/build.py:ffi"],
    zip_safe=False,
)
