import re
from cchardet import UniversalDetector
from enum import IntEnum


bwram_defines = """macro define_bwram(addr, bwram)
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


class WordType(IntEnum):
    OTHER = -1
    ADDR = 1
    COMMA = 2


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
        if encod['confidence'] is not None:
            if encod['confidence'] >= 0.5:
                encoding = encod['encoding']
            else:
                encoding = 'SHIFT_JIS'
        else:
            encoding = 'SHIFT_JIS'      # if confidence is low, try japanese
        try:
            if verbose:
                print(f'Guessed encoding {encoding}, will try to parse now...')
            with open(asmfile, 'r', encoding=encoding) as f:
                text = f.readlines()
        except Exception as e:
            raise e             # propagate
    bw_defs = []
    outputfile = asmfile.replace('.asm', '_sa1.asm')
    outfile = open(outputfile, 'w', encoding=encoding)
    stdout.write(bytes(f'Processing file {asmfile}:\n', encoding=encoding))
    outlines = []
    if opt:
        outfile.write('incsrc conv_defines.asm\n')
    tot_conversions = 0
    for index, line in enumerate(text, start=1):
        outlines.append('')
        data_types = ['db', 'dw', 'dl', 'dd']
        in_comment = False
        in_data = False
        words = re.split(r'([ \t])', line.rstrip())
        if line.strip() == '' or line.lstrip().startswith(';'):
            # shortcuts for comments and blank lines
            outlines[index-1] = line.rstrip()
            continue
        for og_word in words:
            stripped_word = og_word.strip()
            to_insert = ''
            if in_comment or in_data:
                pass
            elif stripped_word.startswith(';'):
                in_comment = True
            elif any([stripped_word.startswith(a) for a in data_types]):
                in_data = True
            elif addr := re.findall(r'\$.{1,6}[|]![^$1-9]+\b', og_word):
                stdout.write(bytes(f'Possibly address {addr[0]} at line {index} was already hybrid.\n',
                             encoding=encoding))
            elif re.findall(r'\$[^, \n()\[\]]{1,6}', og_word):
                splitted = re.split(r'([\[\](), ])', og_word)
                words = []
                for i, word in enumerate(splitted):
                    if word.startswith('$'):
                        try:
                            proc_word = eval(word.replace('$', '0x'))
                            expr = re.split(r'[+\\\-^*~<>|]', word.replace('$', ''))    # +\-^*~<>  some asar math ops
                            word = '${:0{}X}'.format(proc_word, max([len(e) for e in expr]))
                            words.append((WordType.ADDR, word, i))
                        except SyntaxError:
                            bunch = re.split(r'([+\-^*~<>| ])', word)
                            for w in bunch:
                                if w.startswith('$'):
                                    words.append((WordType.ADDR, w, i))
                                else:
                                    words.append((WordType.OTHER, w, i))
                    elif word.startswith(','):
                        words.append((WordType.COMMA, word, i))
                    else:
                        words.append((WordType.OTHER, word, i))
                for wordtype, word, i in words:
                    if wordtype == WordType.ADDR:
                        try:
                            try:
                                comma_index = i+1 if words[i+1][0] == WordType.COMMA else -1
                            except IndexError:
                                comma_index = -1
                            ww, bwram_define_needed, converted = process_word(word.replace('$', ''), stdout, encoding,
                                                                              index, splitted, comma_index)
                            if converted:
                                tot_conversions += 1
                                stdout.write(bytes(f'Conversion: {word} -> {ww}\n', encoding=encoding))
                            bw_defs.append(bwram_define_needed)
                            to_insert += ww
                        except ValueError:
                            to_insert += word
                    else:
                        to_insert += word
            outlines[index-1] += to_insert if to_insert != '' else og_word
    if any(bw_defs):
        outfile.write(bwram_defines)
    # outlines = list(filter(lambda a: a != '', outlines))
    outfile.write('\n'.join(outlines))
    outfile.close()
    if verbose:
        print(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}')
    stdout.write(bytes(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}\n\n\n', encoding=encoding))


def process_word(word, stdout, encoding, index, splitted, comma_index):
    converted = True
    bwram_define_needed = False
    add_dp = False
    special_addr_list = [8366864, 8366876, 8366888, 8366900, 8367006, 8366912, 8366924, 8366936, 8366948, 8367104,
                         8367112, 8367120, 158, 170, 182, 194, 216, 228, 5320, 5332, 5344, 5356, 5368, 5380, 5392, 5404,
                         5416, 5428, 5440, 5452, 5464, 5476, 5488, 5500, 5512, 5524, 5536, 5548, 5560, 5572, 5584, 5596,
                         5610, 5622, 5634, 5646, 5658, 5670, 5682, 5694, 5706, 5718, 5730, 5742, 5754, 5766, 6252, 6267,
                         6415, 6456, 8367872, 8150, 8162]
    bwram_remapped_list = [0x7F9A7B, 0x7027FF]          # Wiggler's segment buffer, Expansion area planned for SMW hacks
    map16_lo_by = (0x7EC800, 0x7EFFFF)                # Map16 low byte plus Overworld related data.
    map16_hi_by = (0x7FC800, 0x7FFFFF)                # Map16 high byte.
    save_mem = (0x700000, 0x7007FF)                # Original save memory (2 kB big). Not everything is used
    bwram_list = [map16_lo_by, map16_hi_by, save_mem]
    if comma_index != -1:
        if len(word) == 4 and (splitted[comma_index+1] == 'y' or splitted[comma_index+1] == 'x') \
                and word[:2] == '00':
            add_dp = True           # preserve absolute addressing when used for some weird reason
    if word.startswith('8') and len(word) == 6:
        word = word.replace('8', '0', 1)
    try:
        int(word, 16)
    except ValueError as e:
        raise e
    # check if it's a dumb bwram remapped address
    bwram_word = int(word, 16) if len(word) == 6 else int('7E' + word, 16)
    if any(baddr[0] <= bwram_word <= baddr[1] for baddr in bwram_list):
        subs = [f'${bwram_word:6X}&$00FFFF|!map16_lo_by', f'${bwram_word:6X}&$00FFFF|!map16_hi_by',
                f'${bwram_word:6X}&$00FFFF|!map16_hi_by']
        bwram_define_needed = True
        for i in range(3):
            if bwram_list[i][0] <= bwram_word <= bwram_list[i][1]:
                word = subs[i]
                break
    elif bwram_word in bwram_remapped_list:
        bwram_define_needed = True
        word = f'!{bwram_word:6X}'
    elif int(word, 16) in special_addr_list:  # if special address, use define
        word = '!' + (f'{int(word, 16):X}' if not add_dp else f'{int(word, 16):X}|!dp')
    elif len(word) == 6 and (0x000000 <= int(word, 16) <= 0x0FFFFF):  # if rom, add !bank
        word = '$' + word + '|!bank'
    elif len(word) == 6 and (0x7E0000 <= int(word, 16) <= 0x7E1FFF):
        word = f'(${word}&$FFFF)|!bankA'
    elif len(word) == 2:  # if direct page, ignore
        converted = False
        word = '$' + word
    elif 0x0100 <= int(word, 16) <= 0x1FFF:  # else, use |!addr
        word = '$' + word + '|!addr'
    elif 0x0000 <= int(word, 16) <= 0x00FF:
        word = '$' + word + '|!dp'
    else:  # if out of range, ignore
        converted = False
        word = '$' + word
        if len(word) == 4:
            stdout.write(bytes(f'Warning: address ${int(word, 16):04X} at line {index} '
                               f'couldn\'t be converted!\n', encoding=encoding))
        elif len(word) == 6:
            stdout.write(bytes(f'Warning: address ${int(word, 16):06X} at line {index} '
                               f'couldn\'t be converted!\n', encoding=encoding))
        else:
            stdout.write(bytes(f'Warning: address ${int(word, 16):X} at line {index} '
                               f'couldn\'t be converted!\n', encoding=encoding))
    return word, bwram_define_needed, converted
