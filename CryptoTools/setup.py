from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_modules = [
    Extension("cipher", ["cipher.py"]),
]

setup(
    name='cipher',
    cmdclass={'build_ext': build_ext},
    ext_modules=ext_modules
)

# python3 build_cipher.py build_ext --inplace
