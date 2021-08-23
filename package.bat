py -m pip install --upgrade pip
py -m pip install -r requirements.txt
pyinstaller.exe --clean --onefile --noupx sa1hybridizer.py
copy conv_defines.asm dist\conv_defines.asm
copy convert_main.py dist\convert_main.py
copy converter.py dist\converter.py
copy sa1hybridizer.py dist\sa1hybridizer.py
cd dist
zip src.zip convert_main.py converter.py sa1hybridizer.py
zip SA1Hybridizer.zip sa1hybridizer.exe src.zip conv_defines.asm
cd ..
move dist\SA1Hybridizer.zip SA1Hybridizer.zip