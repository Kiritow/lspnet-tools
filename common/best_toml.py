import sys
try:
    import tomllib as toml
except ModuleNotFoundError:
    try:
        sys.stderr.write('tomlib not found (python 3.11+), try tomli\n')
        import tomli as toml
    except ModuleNotFoundError:
        sys.stderr.write('tomli not found (pip3 pinstall tomli), try toml\n')
        import toml
