import re
from cchardet import UniversalDetector
from enum import IntEnum
from typing import Tuple


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
sprite_addr_list = [0x7fab10, 0x7fab1c, 0x7fab28, 0x7fab34, 0x7fab9e, 0x7fab40, 0x7fab4c, 0x7fab58, 0x7fab64, 0x7fac00,
                    0x7fac08, 0x7fac10, 0x9e, 0xaa, 0xb6, 0xc2, 0xd8, 0xe4, 0x14c8, 0x14d4, 0x14e0, 0x14ec, 0x14f8,
                    0x1504, 0x1510, 0x151c, 0x1528, 0x1534, 0x1540, 0x154c, 0x1558, 0x1564, 0x1570, 0x157c, 0x1588,
                    0x1594, 0x15a0, 0x15ac, 0x15b8, 0x15c4, 0x15d0, 0x15dc, 0x15ea, 0x15f6, 0x1602, 0x160e, 0x161a,
                    0x1626, 0x1632, 0x163e, 0x164a, 0x1656, 0x1662, 0x166e, 0x167a, 0x1686, 0x186c, 0x187b, 0x190f,
                    0x1938, 0x7faf00, 0x1fd6, 0x1fe2]


class WordType(IntEnum):
    OTHER = -1
    ADDR = 1
    COMMA = 2


def convert(asmfile, opt, verbose, stdout) -> None:
    encoding = 'utf-8'
    requires_manual_conversion = False
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
        define_found = re.match(r'![A-Za-z\d_]+\s+=\s+((\$)?[\dA-Fa-f]{2,6})\S*', line.strip())
        words = re.split(r'([ \t;])', line.rstrip())
        if line.strip() == '' or line.lstrip().startswith(';') or define_found:
            # shortcuts for comments and blank lines and defines
            if define_found:
                requires_manual_conversion = True
                is_hex = define_found.group(2) is not None
                if int(define_found.group(1).replace('$', '0x') if is_hex else define_found.group(1),
                       16 if is_hex else 10) == 12:
                    stdout.write(bytes(f'There is define {define_found.group(0)} at line {index} which is equal to 12,'
                                       f' this might be a define related to how many sprites can be loaded by the game'
                                       f' if so, change it to 22 or $16, or (even better) use the following\n'
                                       f'\tif read1($00FFD5) == $23\n\t\t{define_found.group(0)}\n\telse\n\t\t'
                                       f'{define_found.group(0).split("=")[0]}= {"$16" if is_hex else "22"}\n\tendif\n',
                                       encoding=encoding))
                elif int(define_found.group(1).replace('$', '0x'), 16) in sprite_addr_list and is_hex:
                    stdout.write(bytes(f'There is define {define_found.group(0)} at line {index} which is a sprite '
                                       f'address, usually replacing the $ with ! works in most tools, it didn\'t get '
                                       f'converted automatically because it might not be necessary to do so, make sure '
                                       f'to convert manually it ONLY if needed.\n', encoding=encoding))
                elif 0x0100 <= int(define_found.group(1).replace('$', '0x') if is_hex else define_found.group(1),
                                   16 if is_hex else 10) <= 0x1FFF:
                    stdout.write(bytes(f'There is define {define_found.group(0)} at line {index} which might be a ram'
                                       f' address, if it is, convert it by adding |!addr at the end of it, if it\'s not'
                                       f' a ram address leave it alone\n', encoding=encoding))
            outlines[index-1] = line.rstrip()
            continue
        ignore_next_address = False
        for og_word in words:
            stripped_word = og_word.strip()
            to_insert = ''
            if in_comment or in_data:
                pass
            elif stripped_word.startswith(';'):
                in_comment = True
            elif any([stripped_word.startswith(a) for a in data_types]):
                in_data = True
            elif stripped_word.startswith('PEA') or stripped_word.startswith('PER'):
                ignore_next_address = True
            elif addr := re.findall(r'\$[\da-fA-F]{1,6}\|![a-zA-Z\d_]+\b', og_word):
                stdout.write(bytes(f'Possibly address {addr[0]} at line {index} was already hybrid.\n',
                             encoding=encoding))
            elif re.findall(r'\$[^, \n()\[\]]{1,6}', og_word):
                if ignore_next_address:
                    ignore_next_address = False
                    outlines[index-1] += og_word
                    continue
                splitted = re.split(r'([\[\](), ])', og_word)
                word_tuples = []
                for i, word in enumerate(splitted):
                    if word.startswith('$'):
                        try:
                            proc_word = eval(word.replace('$', '0x'))
                            expr = re.split(r'[+\\\-^*~<>|]', word.replace('$', ''))    # +\-^*~<>  some asar math ops
                            word = '${:0{}X}'.format(proc_word, max([len(e) for e in expr]))
                            word_tuples.append((WordType.ADDR, word, i))
                        except SyntaxError:
                            bunch = re.split(r'([+\-^*~<>| ])', word)
                            for w in bunch:
                                if w.startswith('$'):
                                    word_tuples.append((WordType.ADDR, w, i))
                                else:
                                    word_tuples.append((WordType.OTHER, w, i))
                    elif word.startswith(','):
                        word_tuples.append((WordType.COMMA, word, i))
                    else:
                        word_tuples.append((WordType.OTHER, word, i))
                for wordtype, word, i in word_tuples:
                    if wordtype == WordType.ADDR:
                        try:
                            try:
                                comma_index = i+1 if word_tuples[i+1][0] == WordType.COMMA else -1
                            except IndexError:
                                comma_index = -1
                            ww, bwram_define_needed, converted, manual_conversion = process_word(word.replace('$', ''),
                                                                                                 stdout, encoding,
                                                                                                 index, splitted,
                                                                                                 comma_index)
                            if manual_conversion:
                                requires_manual_conversion = True
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
    outfile.write('\n'.join(outlines))
    outfile.close()
    if verbose:
        print(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}')
        if requires_manual_conversion:
            print(f'File {asmfile} could require manual conversion for some addresses, please check the log file.\n')
    stdout.write(bytes(f'Processed file {asmfile}\nTotal conversions: {tot_conversions}\n\n\n', encoding=encoding))


def check_bwram(word: str) -> Tuple[str, bool]:
    bwram_word = int(word, 16)
    bwram_remapped_list = (0x7F9A7B, 0x7027FF)          # Wiggler's segment buffer, Expansion area planned for SMW hacks
    map16_lo_by = (0x7EC800, 0x7EFFFF)                # Map16 low byte plus Overworld related data.
    map16_hi_by = (0x7FC800, 0x7FFFFF)                # Map16 high byte.
    save_mem = (0x700000, 0x7007FF)                # Original save memory (2 kB big). Not everything is used
    bwram_list = [map16_lo_by, map16_hi_by, save_mem]
    bwram_indexes = [baddr_begin <= bwram_word <= baddr_end for baddr_begin, baddr_end in bwram_list]
    subs = ['map16_lo_by', 'map16_hi_by', 'save_mem']
    if any(bwram_indexes):
        true_index = bwram_indexes.index(True)
        sub = f'${bwram_word:6X}&$00FFFF|!{subs[true_index]}'
        return sub, True
    elif bwram_word in bwram_remapped_list:
        sub = f'!{bwram_word:6X}'
        return sub, True
    return word, False


def check_if_shortable():
    pass


def process_word(word, stdout, encoding, index, splitted, comma_index):
    requires_manual_conversion = False
    converted = True
    add_dp = False
    if comma_index != -1:
        if len(word) == 4 and (splitted[comma_index+1] == 'y' or splitted[comma_index+1] == 'x') \
                and word[:2] == '00':
            add_dp = True           # preserve absolute addressing when used for some weird reason
    if word.startswith('8') and len(word) == 6:
        word = word.replace('8', '0', 1)
    try:
        numeric_word = int(word, 16)  # if it's not a valid hex numeric value, go away
    except ValueError as e:
        raise e

    bwram_define_needed = False
    if len(word) == 6:
        word, bwram_define_needed = check_bwram(word)
    if bwram_define_needed:
        return word, bwram_define_needed, converted, requires_manual_conversion

    if numeric_word in sprite_addr_list:  # if sprite address, use define
        word = '!' + (f'{int(word, 16):X}' if not add_dp else f'{int(word, 16):X}|!dp')
    elif len(word) == 6 and (0x000000 <= numeric_word <= 0x0FFFFF):  # if rom, add !bank
        word = '$' + word + '|!bank'
    elif len(word) == 6 and (0x7E0000 <= numeric_word <= 0x7E1FFF):
        try:
            short_word = word[2:]
            spr_index = sprite_addr_list.index(int(short_word, 16))
            word = f'!{sprite_addr_list[spr_index]:X}'
        except ValueError:
            word = f'(${word}&$FFFF)|!bankA'
    elif len(word) == 2:  # if direct page, ignore
        converted = False
        word = '$' + word
    elif 0x0100 <= numeric_word <= 0x1FFF:  # else, use |!addr
        word = '$' + word + '|!addr'
    elif 0x0000 <= numeric_word <= 0x00FF:
        word = '$' + word + '|!dp'
    else:  # if out of range, ignore
        converted = False
        requires_manual_conversion = True
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
    return word, bwram_define_needed, converted, requires_manual_conversion
