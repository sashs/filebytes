from setuptools import setup, find_packages
import filebytes
version = filebytes.VERSION
package_name = "filebytes"
package_dir = "filebytes"
package_description = """
Scripts to parse the following file formats
- Executable and Linking Format (ELF), Portable Executable (PE), Mach-O and OAT (Android Runtime).
""".strip()

packages = find_packages()
valid_packages = []
for p in packages:
    if p.startswith('filebytes'):
        valid_packages.append(p)

setup(
    name=package_name,
    version=version,
    description=package_description,
    packages=valid_packages,
    license="GPLv2",
    author="Sascha Schirra",
    author_email="sashs@scoding.de",
    url="https://scoding.de/filebytes-introduction/",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python',
        'Intended Audience :: Developers'
    ]
)
