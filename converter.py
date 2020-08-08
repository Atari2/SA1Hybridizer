import re
from chardet.universaldetector import UniversalDetector

bwram_defines = """
macro define_bwram(addr, bwram)
    if read1($00FFD5) == $23
        !<addr> = $<bwram>
    else
        !<addr> = $<addr>
    endif
endmacro
%define_bwram(7F9A7B, 418800) ; ends at 7F9C7A
%define_bwram(700800, 41A000) ; ends at 7027FF
if read1($00FFD5) == $23
    !map16_lo_by = $400000
    !map16_hi_by = $410000
    !save_mem = $41C000
else
    !map16_lo_by = $7E0000
    !map16_hi_by = $7F0000
    !save_mem = $700000
endif
"""


def convert(asmfile, opt, verbose, stdout) -> None:
    encoding = 'utf-8'
    try:
        with open(asmfile, 'r') as f:
            text = f.readlines()
    except Exception as e:
        detector = UniversalDetector()
        for line in open(asmfile, 'rb'):
            detector.feed(line)
            if detector.done:
                break
        detector.close()
        encod = detector.result
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
    bwram_define_needed = False
    outputfile = asmfile.replace('.asm', '_sa1.asm')
    outfile = open(outputfile, 'w', encoding=encoding)
    stdout.write(bytes(f'Processing file {asmfile}:\n', encoding=encoding))
    outlines = []
    if opt:
        outfile.write('incsrc conv_defines.asm\n')
    special_addr_list = [8366864, 8366876, 8366888, 8366900, 8367006, 8366912, 8366924, 8366936, 8366948, 8367104,
                         8367112, 8367120, 158, 170, 182, 194, 216, 228, 5320, 5332, 5344, 5356, 5368, 5380, 5392, 5404,
                         5416, 5428, 5440, 5452, 5464, 5476, 5488, 5500, 5512, 5524, 5536, 5548, 5560, 5572, 5584, 5596,
                         5610, 5622, 5634, 5646, 5658, 5670, 5682, 5694, 5706, 5718, 5730, 5742, 5754, 5766, 6252, 6267,
                         6415, 6456, 8367872, 8150, 8162]
    bwram_remapped_list = [0x7F9A7B, 0x7027FF]          # Wiggler's segment buffer, Expansion area planned for SMW hacks
    map16_lo_by = (0x7EC800, 0x7EFFFF)                # Map16 low byte plus Overworld related data.
    map16_hi_by = (0x7FC800, 0x7FFFFF)                # Map16 high byte.
    save_mem = (0x700000, 0x7007FF)                # Original save memory (2 kB big). Not everything is used
    tot_conversions = 0
    whole_file = '\n'.join(text)
    for index, line in enumerate(text, start=1):
        outlines.append('')
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
                outlines[index-1] = line
                continue
        for n_word, og_word in enumerate(words):
            converted = False
            to_insert = ''
            if og_word.startswith(';'):
                in_comment = True
            elif og_word.startswith('db') or og_word.startswith('dw') or og_word.startswith('dl'):
                in_data = True
            elif re.match(r'\$?.{1,6}[|]!?.+\b', og_word) and not in_comment and not in_data:
                stdout.write(bytes(f'Possibly address {og_word} at line {index} was already hybrid.\n',
                             encoding=encoding))
            elif not in_comment and not in_data and re.findall(r'\$[^, \n()\[\]]{1,6}', og_word):
                splitted = re.split(r'([\[\](),])', og_word)
                addr_index = -1
                comma_index = -1
                add_dp = False
                immediate_value = False
                for i, word in enumerate(splitted):
                    if word.startswith('$'):
                        addr_index = i
                    elif word.startswith(','):
                        comma_index = i
                    elif word.find('#') != -1:
                        immediate_value = True
                if immediate_value:
                    outlines[index-1] += (spaces[n_word] + og_word)
                    break
                if addr_index == -1:
                    raise Exception('An unexpected error happened, please report to the author')
                word = splitted[addr_index].replace('$', '')
                if comma_index != -1:
                    if len(word) == 4 and (splitted[comma_index+1] == 'y' or splitted[comma_index+1] == 'x')\
                            and word[:2] == '00':
                        add_dp = True
                if word.startswith('8') and len(word) == 6:
                    word = word.replace('8', '0', 1)
                try:
                    int(word, 16)
                except ValueError:
                    stdout.write(bytes(f'Couldn\'t convert {word} to integer on line {index}\n', encoding=encoding))
                    outlines[index-1] += (spaces[n_word] + og_word)
                    continue
                # check if it's a dumb bwram remapped address
                bwram_word = word if len(word) == 6 else '7E'+word
                bwram_word_int = int(bwram_word, 16)
                if map16_lo_by[0] <= bwram_word_int <= map16_lo_by[1]:
                    converted = True
                    bwram_define_needed = True
                    word = f'${bwram_word}&$00FFFF|!map16_lo_by'
                elif map16_hi_by[0] <= bwram_word_int <= map16_hi_by[1]:
                    converted = True
                    bwram_define_needed = True
                    word = f'${bwram_word}&$00FFFF|!map16_hi_by'
                elif save_mem[0] <= bwram_word_int <= save_mem[1]:
                    converted = True
                    bwram_define_needed = True
                    word = f'${bwram_word}&$000FFF|!save_mem'
                elif bwram_word_int in bwram_remapped_list:
                    converted = True
                    bwram_define_needed = True
                    word = '!' + bwram_word
                elif int(word, 16) in special_addr_list:  # if special address, use define
                    converted = True
                    word = '!' + (f'{int(word, 16):X}' if not add_dp else f'{int(word, 16):X}|!dp')
                elif len(word) == 6 and (0x008000 <= int(word, 16) <= 0x0FFFFF):  # if rom, add !bank
                    converted = True
                    word = '$' + word + '|!bank'
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
                for i, sub in enumerate(splitted):
                    if i == addr_index:
                        to_insert += word
                    else:
                        to_insert += sub
            if converted:
                tot_conversions += 1
                stdout.write(bytes(f'Conversion: {og_word} -> {to_insert}\n', encoding=encoding))
                outlines[index-1] += (spaces[n_word] + to_insert)
            else:
                outlines[index-1] += (spaces[n_word] + og_word)
    if bwram_define_needed:
        outfile.write(bwram_defines)
    outfile.write('\n'.join(outlines))
    outfile.close()
    if verbose:
        print(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}')
    stdout.write(bytes(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}\n\n\n', encoding=encoding))
