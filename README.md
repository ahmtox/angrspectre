# Installation Instructions 

We are using an older verison of angr because it much easier to work with than the latest version. However, there are clear paths towards refactoring for the latest angr version. It might be complicated to implement the appropriate IR and Store hooks however.

I recommend using pyenv and using Python 3.6.15 for version control. This makes it substantially easier to work with angr.

```
python3.6 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install angr==8.19.4.5

cd angrspectre/
python main.py
```

Results are in `results.txt`