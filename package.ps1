py -m pip install --upgrade pip
$pyinstaller_loc = py -m pip install -r requirements.txt | Select-String -Pattern "are installed in '(.+)'" -AllMatches | ForEach-Object {$_.Matches[0].Groups[1].Value}
$pyinstaller_loc = $pyinstaller_loc + "\pyinstaller.exe"
Invoke-Expression "$pyinstaller_loc --clean --onefile --noupx sa1hybridizer.py"
Copy-Item conv_defines.asm dist\conv_defines.asm
Copy-Item convert_main.py dist\convert_main.py
Copy-Item converter.py dist\converter.py
Copy-Item sa1hybridizer.py dist\sa1hybridizer.py
Set-Location dist
Compress-Archive -Path convert_main.py,converter.py,sa1hybridizer.py -DestinationPath src.zip
Compress-Archive -Path sa1hybridizer.exe,src.zip,conv_defines.asm -DestinationPath SA1Hybridizer.zip
Set-Location ..
Move-Item dist\SA1Hybridizer.zip SA1Hybridizer.zip