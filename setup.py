from setuptools import setup
import ast
import os
currentDir = os.path.dirname(os.path.abspath(__file__))
#currentDir = Path(__file__).parent

def extractMetaInfo(src):
    info = {}
    a=ast.parse(src)
    for e in a.body:
        if isinstance(e, ast.Assign) and isinstance(e.value, ast.Str):
            info[e.targets[0].id] = e.value.s
    return info

text = ''
with open(currentDir  +os.path.sep+"filebytes"+ os.path.sep+"__init__.py") as f:
    text = f.read()

version = extractMetaInfo(text)["VERSION"]


setup(version=version)
