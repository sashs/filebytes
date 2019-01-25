from setuptools import setup
import ast
from pathlib import Path

currentDir = Path(__file__).parent

def extractMetaInfo(src):
    info = {}
    a=ast.parse(src)
    for e in a.body:
        if isinstance(e, ast.Assign) and isinstance(e.value, ast.Str):
            info[e.targets[0].id] = e.value.s
    return info

version = extractMetaInfo((currentDir / "filebytes" / "__init__.py").read_text())["VERSION"]

setup(version=version)
