# Installation Instructions 

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