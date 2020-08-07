import sys
import converter
import zipfile
import glob
import io

print('This tool assumes that whatever is being converted is gonna use the standard defines (Pixi, GPS, UberasmTool)\n'
      'If that\'s not the case, you can run this on command line adding "--def" before the filename and then using '
      '"conv_defines.asm" with the converted file.\nThis tool can convert also zip files, it will unzip and attempt '
      'to convert every .asm file that it finds in that folder.\nSince the output is extremely verbose, it is '
      'recommended to use single files only.\nAlternatively, you can use --silence in the command line to silence all '
      'outputs.')
opt = False
verbose = True
if len(sys.argv) == 2:
    asmfile = sys.argv[1]
elif len(sys.argv) == 3:
    opt = True if sys.argv[1] == '--def' else False
    verbose = False if sys.argv[1] == '--silence' else True
    asmfile = sys.argv[2]
elif len(sys.argv) == 4:
    if any(arg == '--def' for arg in sys.argv):
        opt = True
    if any(arg == '--silence' for arg in sys.argv):
        verbose = False
    asmfile = sys.argv[3]
else:
    asmfile = input('Insert the name of the file you wish to convert:\n')

stdout = open('results.log', 'wb') if verbose else io.BytesIO()

if zipfile.is_zipfile(asmfile):
    with zipfile.ZipFile(asmfile, 'r') as z:
        z.extractall(asmfile.replace('.zip', ''))
    directory = asmfile.replace('.zip', '')
    processed = 0
    errored = 0
    for file in glob.glob(f'{directory}/**/*.asm', recursive=True):
        try:
            if verbose:
                print(f'Processing file {file}')
            converter.convert(file, opt, verbose, stdout)
            processed += 1
        except Exception as e:
            stdout.write(bytes(f'File {file} errored: {str(e)}\n\n\n', encoding='utf-8'))
            if verbose:
                print(f'{file} generated exception {str(e)}')
            errored += 1
    print(f'Total processed files {processed}, errored files {errored}')
else:
    try:
        print(f'Processing file {asmfile}')
        converter.convert(asmfile, opt, verbose, stdout)
    except Exception as e:
        stdout.write(bytes(f'File {asmfile} errored: {str(e)}\n\n\n', encoding='utf-8'))
        print(f'File {asmfile} errored: {str(e)}')
stdout.close()
input(f'{"Conversion details in log file" if verbose else "Silence mode was used"}\nPress any key to exit\n')
