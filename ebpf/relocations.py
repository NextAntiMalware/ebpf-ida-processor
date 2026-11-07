import idaapi

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from ebpf.constants import REL_TYPE, REL_PATCH_SIZE
from ebpf.config import STRINGS_PREVIEW_LIMIT
from ebpf.strings import add_string
from ebpf.helpers import decode_name

def parse_relocation(rel_type, loc, val):
    type_ = REL_TYPE[rel_type]
    changes = []
    if type_ == 'R_BPF_64_64':
        changes.append({'loc': loc + 4, 'val': val & 0xFFFFFFFF})
        changes.append({'loc': loc + 8 + 4, 'val': val >> 32})
    elif type_ == 'R_BPF_64_ABS64':
        changes.append({'loc': loc, 'val': val})
    elif type_ == 'R_BPF_64_ABS32':
        pass
    elif type_ == 'R_BPF_64_NODYLD32':
        changes.append({'loc': loc, 'val': val & 0xFFFFFFFF})
    elif type_ == 'R_BPF_64_32':
        changes.append({'loc': loc + 4, 'val': val & 0xFFFFFFFF})
    else:
        print(f'[WARN] unknown relocation type: {type_}')
    
    return changes

def _sym_ea(sections, relsym):
    """把符号解析成 IDA 地址：目标节基址 + st_value。"""
    try:
        shndx = relsym.get('shndx')
        if not isinstance(shndx, int) or shndx <= 0 or shndx >= len(sections):
            return None
        s = sections[shndx]
        ea = idaapi.get_fileregion_ea(s.header['sh_offset'] + relsym['val'])
        return None if ea == idaapi.BADADDR else ea
    except Exception:
        return None


def process_relocations(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        sections = []
        for section in elffile.iter_sections():
            sections.append(section)

        relocations = {}
        functions = {}
        rodata = {}

        symtab_s = elffile.get_section_by_name('.symtab')
        symtab = []

        if symtab_s:
            for sym in symtab_s.iter_symbols():
                symtab.append({'name': sym.name, 'val': sym.entry['st_value'],
                               'size': sym.entry['st_size'],
                               'shndx': sym.entry['st_shndx']})
                    
        for s in sections:
            # BTF 相关重定位与指令无关，跳过；它们引用的节 IDA 不加载，地址会是 BADADDR
            if '.BTF' in s.name:
                continue

            # dynamic
            if s.header['sh_type'] == 'SHT_REL' and s.name == '.rel.dyn':
                dynsym = elffile.get_section_by_name(".dynsym")
                if not dynsym or not isinstance(dynsym, SymbolTableSection):
                    print("dynsym not found. what?")
                    continue
                
                symbols = []
                for symbol in dynsym.iter_symbols():
                    symbols.append({'name': symbol.name, 'val': symbol.entry['st_value'],
                                    'shndx': symbol.entry['st_shndx']})
                
                for reloc in s.iter_relocations():
                    relsym = symbols[reloc['r_info_sym']]

                    name = decode_name(relsym['name'])

                    reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                    mods = []

                    for r in reloc_parsed:
                        mods.append({'loc': idaapi.get_fileregion_ea(r['loc']), 'val': r['val']})
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods,
                        'target': _sym_ea(sections, relsym),
                    }

                    relocations[idaapi.get_fileregion_ea(reloc['r_offset'])] = relocation
                    
                continue

            if s.header['sh_type'] == 'SHT_REL':
                if not symtab_s:
                    print("symtab section not found. what?")
                    continue

                code_s = sections[s.header['sh_info']]
                base_offset = code_s.header['sh_offset']

                section_name = decode_name(s.name)
                ea_addr = idaapi.get_fileregion_ea(base_offset)
                if s.name.startswith('.rel.text.'):
                    functions[section_name] = ea_addr
                elif s.name.startswith('.rel.data.rel.ro.'):
                    rodata[section_name] = ea_addr

                for reloc in s.iter_relocations():
                    relsym = symtab[reloc['r_info_sym']]

                    name = decode_name(relsym['name'])

                    reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                    mods = []

                    for r in reloc_parsed:
                        mods.append({'loc': idaapi.get_fileregion_ea(base_offset + r['loc']), 'val': r['val']})
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods,
                        'target': _sym_ea(sections, relsym),
                    }

                    relocations[idaapi.get_fileregion_ea(base_offset + reloc['r_offset'])] = relocation

        return relocations, functions, rodata, symtab

def apply_rel_mods(mods, patch_size):
    for mod in mods:
        if mod['val'] != 0:
            if patch_size == 32:
                idaapi.patch_dword(mod['loc'], mod['val'])
            elif patch_size == 64:
                idaapi.patch_qword(mod['loc'], mod['val'])
            else:
                print('[ERROR] apply relocation: none type')

def apply_relocation(functions, rodata, sorted_strings, insn, relocation):
    """应用一条重定位。

    - R_BPF_64_32（call）：优先用 process_relocations 解析好的 target
    - R_BPF_64_64（lddw）：把 map/全局符号的地址写进指令并加 dref
    解析不了就跳过，绝不让空符号名导致 KeyError。
    """
    rtype = REL_TYPE.get(relocation.get('type'))
    patch_size = REL_PATCH_SIZE.get(relocation.get('type'))
    mods = relocation.get('mods') or []
    name = relocation.get('name') or ''

    if rtype == 'R_BPF_64_32':  # call
        target = relocation.get('target')
        if target is None and name:
            target = functions.get(name)
        if target is not None:
            insn.add_cref(target, insn[0].offb, idaapi.fl_CF)
        return sorted_strings

    if patch_size:
        apply_rel_mods(mods, patch_size)

    if rtype == 'R_BPF_64_64':  # lddw / map 引用
        data_addr = rodata.get(name) or functions.get(name)
        if data_addr:
            m2 = parse_relocation(relocation['type'], insn.ea, data_addr)
            apply_rel_mods(m2, patch_size)
            insn.add_dref(data_addr, insn[1].offb, idaapi.dr_R)

    return sorted_strings
