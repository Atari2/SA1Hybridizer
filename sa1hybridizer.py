import converter
import zipfile
import glob
import io
import argparse

parser = argparse.ArgumentParser(description='This tool by default assumes that the file being converted is gonna use\
                                              the standard Pixi defines',
                                 epilog='This tool can also convert zip files, converting every asm files that it finds\
                                         inside them. However since the output is extremely verbose, it\'s recommended\
                                         to add the silence option when working with zips')
parser.add_argument("-d", "--defines", help="Adds the defines at the top of the converted patch", action="store_true")
parser.add_argument("-s", "--silence", help="Removes all verbosity from output", action="store_true")
parser.add_argument("-f", "--asmfile", help="The name of the asm file you're converting", default=None)
args = parser.parse_args()
parser.print_help()
opt = args.defines
verbose = not args.silence
asmfile = args.asmfile or input('Insert the name of the file you wish to convert:\n')

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
input(f'{"Conversion details in log file" if verbose else "Silence mode was used"}\nPress enter to exit\n')
