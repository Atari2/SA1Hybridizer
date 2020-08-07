import re
import chardet

bwram_defines = """macro define_bwram(addr, bwram)
    if read1($00FFD5) == $23
        !<addr> = $<bwram>
    else
        !<addr> = $<addr>
    endif
endmacro
%define_bwram(7E0100, 400100) ; ends at 7E010A
%define_bwram(7E0200, 400200) ; ends at 7E1FFF
%define_bwram(7EC800, 40C800) ; ends at 7EFFFF
%define_bwram(7F9A7B, 418800) ; ends at 7F9C7A
%define_bwram(700000, 41C000) ; ends at 7007FF
%define_bwram(7FC800, 41C800) ; ends at 7FFFFF
"""


def convert(asmfile, opt, verbose, stdout) -> None:
    encoding = 'utf-8'
    try:
        with open(asmfile, 'r') as f:
            text = f.readlines()
    except Exception as e:
        with open(asmfile, 'rb') as det:
            rawdata = det.read()
        encod = chardet.detect(rawdata)
        if encod['confidence'] > 0.5:
            encoding = encod['encoding']
        else:
            encoding = 'SHIFT_JIS'      # if confidence is low, try japanese
        try:
            if verbose:
                print(f'Guessed encoding {encoding}, will try to parse now...')
            with open(asmfile, 'r', encoding=encoding) as f:
                text = f.readlines()
        except Exception as e:
            raise e             # propagate

    outputfile = asmfile.replace('.asm', '_sa1.asm')
    outfile = open(outputfile, 'w', encoding=encoding)
    stdout.write(bytes(f'Processing file {asmfile}:\n', encoding=encoding))
    outfile.write(bwram_defines)
    if opt:
        outfile.write('incsrc conv_defines.asm\n')
    special_addr_list = [8366864, 8366876, 8366888, 8366900, 8367006, 8366912, 8366924, 8366936, 8366948, 8367104,
                         8367112, 8367120, 158, 170, 182, 194, 216, 228, 5320, 5332, 5344, 5356, 5368, 5380, 5392, 5404,
                         5416, 5428, 5440, 5452, 5464, 5476, 5488, 5500, 5512, 5524, 5536, 5548, 5560, 5572, 5584, 5596,
                         5610, 5622, 5634, 5646, 5658, 5670, 5682, 5694, 5706, 5718, 5730, 5742, 5754, 5766, 6252, 6267,
                         6415, 6456, 8367872, 8150, 8162]
    bwram_remapped_list = [(0x7E0100, 0x7E010A), (0x7E0200, 0x7E1FFF), (0x7EC800, 0x7EFFFF), (0x700000, 0x7007FF),
                           (0x7FC800, 0x7FFFFF)]
    tot_conversions = 0
    whole_file = '\n'.join(text)
    for index, line in enumerate(text, start=1):
        in_comment = False
        in_data = False
        words = line.rstrip().split()
        spaces = ['']
        i = 0
        prev_char_space = True
        for char in line:
            if char == ' ' or char == '\t':
                prev_char_space = True
                spaces[i] += char
            elif prev_char_space:
                prev_char_space = False
                spaces.append('')
                i += 1
        if line.startswith('!'):
            define = line[:line.find('=')].strip()
            def_patt = re.compile(rf'#{re.escape(define)},?[x|y]?\b')
            if re.findall(def_patt, whole_file):
                outfile.write(line)
                continue
        for n_word, og_word in enumerate(words):
            converted = False
            word = ''
            if og_word.startswith(';'):
                in_comment = True
            elif og_word.startswith('db') or og_word.startswith('dw') or og_word.startswith('dl'):
                in_data = True
            elif re.match(r'\$?.{1,6}[|]!?.+\b', og_word) and not in_comment and not in_data:
                stdout.write(bytes(f'Possibly address {og_word} at line {index} was already hybrid.\n',
                             encoding=encoding))
            elif not in_comment and not in_data and og_word.startswith('$'):
                splitted = og_word.split(',')
                word = splitted.pop(0).replace('$', '')
                try:
                    int(word, 16)
                except ValueError as e:
                    stdout.write(bytes(f'Couldn\'t convert {word} to integer on line {index}\n', encoding=encoding))
                    outfile.write(og_word + ' ')
                    continue
                # check if it's a dumb bwram remapped address
                bwram_word = word if len(word) == 6 else '7E'+word
                if any([bwram_addr[0] <= int(bwram_word, 16) <= bwram_addr[1] for bwram_addr in bwram_remapped_list]):
                    converted = True
                    word = '!' + bwram_word
                elif int(word, 16) in special_addr_list:  # if special address, use define
                    converted = True
                    word = '!' + word
                elif len(word) == 6 and (0x008000 <= int(word, 16) <= 0x0FFFFF):  # if rom, add !bank
                    converted = True
                    word += '|!bank'
                elif len(word) == 2:  # if direct page, ignore
                    pass
                elif 0x0100 < int(word, 16) <= 0x1FFF:  # else, use |!addr
                    converted = True
                    word = '$' + word + '|!addr'
                elif 0x0000 <= int(word, 16) <= 0x00FF:
                    converted = True
                    word = '$' + word + '|!dp'
                else:  # if out of range, ignore
                    if len(word) == 4:
                        stdout.write(bytes(f'Warning: address ${int(word, 16):04X} at line {index} '
                                           f'couldn\'t be converted!\n', encoding=encoding))
                    elif len(word) == 6:
                        stdout.write(bytes(f'Warning: address ${int(word, 16):06X} at line {index} '
                                           f'couldn\'t be converted!\n', encoding=encoding))
                    else:
                        stdout.write(bytes(f'Warning: address ${int(word, 16):X} at line {index} '
                                           f'couldn\'t be converted!\n', encoding=encoding))
                for sub in splitted:
                    word = word + ',' + sub
            if converted:
                tot_conversions += 1
                stdout.write(bytes(f'Conversion: {og_word} -> {word}\n', encoding=encoding))
                outfile.write(spaces[n_word] + word)
            else:
                outfile.write(spaces[n_word] + og_word)
        outfile.write('\n')
    outfile.close()
    if verbose:
        print(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}')
    stdout.write(bytes(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}\n\n\n', encoding=encoding))
