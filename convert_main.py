import converter
import zipfile
import glob

def convert_main(asmfile, verbose, stdout, opt):
    if zipfile.is_zipfile(asmfile):
        with zipfile.ZipFile(asmfile, "r") as z:
            z.extractall(asmfile.replace(".zip", ""))
        directory = asmfile.replace(".zip", "")
        processed = 0
        errored = 0
        for file in glob.glob(f"{directory}/**/*.asm", recursive=True):
            try:
                if verbose:
                    print(f"Processing file {file}")
                converter.convert(file, opt, verbose, stdout)
                processed += 1
            except Exception as e:
                stdout.write(
                    bytes(f"File {file} errored: {str(e)}\n\n\n", encoding="utf-8")
                )
                if verbose:
                    print(f"{file} generated exception {str(e)}")
                errored += 1
        print(f"Total processed files {processed}, errored files {errored}")
    else:
        try:
            print(f"Processing file {asmfile}")
            converter.convert(asmfile, opt, verbose, stdout)
        except Exception as e:
            stdout.write(bytes(f"File {asmfile} errored: {str(e)}\n\n\n", encoding="utf-8"))
            print(f"File {asmfile} errored: {str(e)}")
    stdout.close()
    input(
        f'{"Conversion details in log file" if verbose else "Silence mode was used"}\nPress enter to exit\n'
    )