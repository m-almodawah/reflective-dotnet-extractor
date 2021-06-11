import binascii
import textwrap
import pefile
import hashlib
import mmap
import re
from tabulate import tabulate
import os
import sys
import argparse
from pathlib import Path

SECTION_SIZE = 0x28
COFF_SIZE = 0x18
MZ_SIG = [0x4d,0x5a]
PE_HEADER_POINTER = 0x3c
PE_SIG = [0x50,0x45]
OPTIONAL_HEADERS_OFFSET = 0x14
NUMBER_OF_SECTIONS_OFFSET = 0x06
SIZE_OF_RAW_DATA_OFFSET = 0x10
POINTER_TO_RAW_DATA_OFFSET = 0x14

def mz_check(payload):
    if payload[0] == MZ_SIG[0] and payload[1] == MZ_SIG[1]:
        return True
    else:
        return False

def get_pe_header_pointer(payload):
    pointer = payload[PE_HEADER_POINTER:PE_HEADER_POINTER + 4]
    pointer = int.from_bytes(pointer, byteorder='little', signed=False)
    return pointer

def pe_sig_check(payload):
    pointer = get_pe_header_pointer(payload)
    if pointer >= len(payload) - 4:
        return False
    sig = payload[pointer:pointer + 4]
    if sig[0] == PE_SIG[0] and sig[1] == PE_SIG[1] and sig[2] == 0x0 and sig[3] == 0x0:
        return True

def get_sizeof_optional_headers(payload):
    pointer = get_pe_header_pointer(payload)
    size = payload[pointer + OPTIONAL_HEADERS_OFFSET:pointer + OPTIONAL_HEADERS_OFFSET + 2]
    size = int.from_bytes(size, byteorder='little', signed=False)
    return size

def get_number_of_sections(payload):
    pointer = get_pe_header_pointer(payload)
    number = payload[pointer + NUMBER_OF_SECTIONS_OFFSET:pointer + NUMBER_OF_SECTIONS_OFFSET + 2]
    number = int.from_bytes(number, byteorder='little', signed=False)
    return number

def get_last_section_offset(payload):
    pointer = get_pe_header_pointer(payload)
    optional_headers_offset = pointer + COFF_SIZE
    optional_headers_size = get_sizeof_optional_headers(payload)
    first_section_header_offset = optional_headers_offset + optional_headers_size
    num_of_sections = get_number_of_sections(payload)
    last_section_header_offset = first_section_header_offset + (SECTION_SIZE * (num_of_sections - 1))
    return last_section_header_offset

def get_file_size(payload):
    last_section_offset = get_last_section_offset(payload)
    SizeOfRawData = payload[last_section_offset + SIZE_OF_RAW_DATA_OFFSET:last_section_offset + SIZE_OF_RAW_DATA_OFFSET + 4]
    PointerToRawData = payload[last_section_offset + POINTER_TO_RAW_DATA_OFFSET:last_section_offset + POINTER_TO_RAW_DATA_OFFSET + 4]
    SizeOfRawData = int.from_bytes(SizeOfRawData, byteorder='little', signed=False)
    PointerToRawData = int.from_bytes(PointerToRawData, byteorder='little', signed=False)
    file_size = PointerToRawData + SizeOfRawData
    return file_size

def check_mscoree(pe):
    if "mscoree.dll._CorDllMain" in str(pe):
        return True
    else:
        return False

def pe_dump(pe_raw,name, out_dir):
    if ".dll" not in name[-4:]:
        name=name+".dll"
    file_name = os.path.join(out_dir, name)
    fd = open(file_name,"wb")
    fd.write(pe_raw)
    fd.close()

def get_pe_file_name(pe):
    if hasattr(pe, 'VS_VERSIONINFO'):
        if hasattr(pe, 'FileInfo'):
            for finfo in pe.FileInfo:
                for entry in finfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for key, entry in list(st_entry.entries.items()):
                                if key.decode("utf-8") == "OriginalFilename":
                                    return entry.decode("utf-8")
    return "unknown"

def get_md5_hash(pe_raw):
    mymd5 = hashlib.md5(pe_raw)
    return mymd5.hexdigest()

def get_file_paths(file_name):
    ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
    paths = []
    fd = open(file_name,"rb")
    searcher = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
    myreg = "((?:[%s]\x00){%d,})" % (ASCII_BYTE, 8)
    uni_re = re.compile(myreg.encode())
    for match in uni_re.finditer(searcher):
        try:
            utf16str = match.group(0).decode("utf-16")
            if ":\\" in utf16str and "file:///" not in utf16str and len(utf16str) < 300:
                paths.append(utf16str)
        except:
            0
    return paths

def get_mz_offsets(file_name):
    offsets = []
    fd = open(file_name,"rb")
    searcher = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
    mzre = re.compile("MZ".encode())
    for result in mzre.finditer(searcher):
        offsets.append(result.start())
    return offsets

def read_block(file_name, offset, size):
    fd = open(file_name, "rb")
    fd.seek(offset)
    block = fd.read(size)
    fd.close()
    return block

def get_path(dllname,paths):
    dllname = "\\"+dllname
    for path in paths:
        if dllname in path:
            return path
    return "[Reflective Loading]"

def get_modload_type(path):
    if "[Reflective Loading]" in path:
        return path
    else:
        return "[Local File Loading]"

def is_file_load(path):
    return "[Reflective Loading]" not in path

def is_reflective_load(path):
    return "[Reflective Loading]" in path

def main(file_name, out_dir):
    print("\nAuthor: Mohammed Almodawah\n")
    print(".Net Assembly Dumper V 1.0\n")
    sys.stdout.write("Locating PE Headers...")
    sys.stdout.flush()
    mz_offsets = get_mz_offsets(file_name)
    sys.stdout.write("\rExtracting DLL File Paths...")
    sys.stdout.flush()
    paths = get_file_paths(file_name)
    sys.stdout.write("\rDumping .Net Assemblies...\n")
    sys.stdout.flush()

    mz_hashes = []
    dllfound = False
    for mz_offset in mz_offsets:
        payload = read_block(file_name, mz_offset, 4096 * 2)
        if mz_check(payload):
            if pe_sig_check(payload):
                pe_size = get_file_size(payload)
                pe_raw = read_block(file_name,mz_offset,pe_size)
                try:
                    pe = pefile.PE(data=pe_raw)
                except:
                    continue
                if check_mscoree(pe):
                    dllhash = get_md5_hash(pe_raw)
                    if dllhash not in mz_hashes:
                        dllfound = True
                        mz_hashes.append(dllhash)
                        dllname = get_pe_file_name(pe)
                        dllpath = get_path(dllname, paths)
                        modload = get_modload_type(dllpath)
                        pe_dump(pe_raw,dllhash+"_"+dllname, out_dir)
                        table = []
                        table.append(["File Name:",dllname])
                        table.append(["MD5 Hash:",dllhash])
                        table.append(["Load Type:",modload])
                        if is_file_load(dllpath):
                            table.append(["File Path:",dllpath])
                        print("")
                        print(tabulate(table, tablefmt="plain"))
    if not dllfound:
        print("No .Net Assemblies Found")

parser = argparse.ArgumentParser(description = ".Net Assembly Dumper V 1.0. Author: Mohammed Almodawah. This tool allows you to dump .Net Assemblies from a process memory dump.")
parser.add_argument("File", help="Path to your process memory dump file")
parser.add_argument("Directory", help="Path of where you want to dump the extracted .Net Assemblies")
args = parser.parse_args()

main(args.File, args.Directory)
