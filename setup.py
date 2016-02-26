from setuptools import setup, find_packages

version = '0.8.0'
package_name = "filebytes"
package_dir = "filebytes"
package_description = """
Scripts to parse the following file formats:
- Executable and Linkage Format (ELF),
- Portable Executable (PE) and
- Mach-O
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
    url="http://github.com/sashs/filebytes/",
    classifiers=[
        'Topic :: Software Development',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python',
        'Intended Audience :: Developers'
    ]
)
