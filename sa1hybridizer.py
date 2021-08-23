import io
import argparse
from sys import argv
from convert_main import convert_main


# if file was dragged onto the exe, just convert it and exit
if len(argv) == 2:
    asmfile = argv[1]
    convert_main(asmfile, True, io.BytesIO(), True)
    quit()

parser = argparse.ArgumentParser(
    description="This tool by default assumes that the file being converted is gonna use the standard Pixi defines",
    epilog="This tool can also convert zip files, converting every asm files that it finds inside them. However since "
           "the output is extremely verbose, it's recommended to add the silence option when working with zips. Note "
           "that the command line options are only valid when executed throught the command line and not needed when "
           "double-clicked.",
)
parser.add_argument(
    "-d",
    "--defines",
    help="Adds the defines at the top of the converted patch",
    action="store_true",
)
parser.add_argument(
    "-s", "--silence", help="Removes all verbosity from output", action="store_true"
)
parser.add_argument(
    "-f", "--asmfile", help="The name of the asm file you're converting", default=None
)
args = parser.parse_args()
parser.print_help()
opt = args.defines
verbose = not args.silence
asmfile = args.asmfile or input("Insert the name of the file you wish to convert:\n")

stdout = open("results.log", "wb") if verbose else io.BytesIO()

convert_main(asmfile, verbose, stdout, opt)