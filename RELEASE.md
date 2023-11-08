# Releasing Updates

## Things you'll need

* PyPI Publishing Token
* Build tools: `python3 -m pip install --upgrade build`
* Twine: `python3 -m pip install --upgrade twine`

## Releasing

Make changes & update version number

```bash
python3 -m build
python3 -m twine upload dist/*
```
When it asks for username password:

```bash
username: __token__
password: $PYPI_PUBLISHING_TOKEN
```