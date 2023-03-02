import subprocess
import lief 
import os
import json
class Checker:
    def __init__(self, file_path):
        self.dumpbin_path = r'\path\to\dumpbin.exe'
        self.file_path = file_path
        self.binary = lief.parse(file_path)
        self.optional_header = self.binary.optional_header
        self.characteristics = self.optional_header.dll_characteristics_lists
    def check_vuln_functions(self):
        v_fs = ['gets', 'strcpy', 'sprintf', 'scanf', 'sscanf', 'strcat', 'strncat', 'strncpy', 'memcpy', 'memmove', 'sprintf', 'vsprintf', 'vsnprintf', 'vswprintf', 'wcscat', 'wcsncat', 'wcscpy', 'wcsncpy', 'wmemcpy', 'wmemmove', 'swprintf', 'snprintf', 'strtok', 'strtok_s', 'wcstok', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s', 'strcat_s', 'wcscat_s', 'wcsncat_s', 'wcscpy_s', 'wcsncpy_s', 'strncat_s', 'strncpy_s']
        potential_vuln_functions = []
        checksec_output = subprocess.check_output([self.dumpbin_path, '/symbols', self.file_path])
        parsed_output = checksec_output.decode('utf-8').splitlines()
        for line in parsed_output:
            for v_f in v_fs:
                if v_f in line:
                    potential_vuln_functions.append(line)
        return potential_vuln_functions
    def check_dll_characteristics(self):
        return lief.PE.DLL_CHARACTERISTICS.NX_COMPAT in self.characteristics
    def check_aslr(self):
        return lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE in self.characteristics
    def check_seh(self):
        return lief.PE.DLL_CHARACTERISTICS.NX_COMPAT in self.characteristics
    def check_safe_seh(self):
        return lief.PE.DLL_CHARACTERISTICS.NO_SEH in self.characteristics
    def check_high_entropy_va(self):
        return lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA in self.characteristics
    def check_force_integrity(self):
        return lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY in self.characteristics
    def check_relro(self):
        try:
            self.elf.get(lief.ELF.DYNAMIC_TAGS.GNU_RELRO)
            return True
        except:
            return False
    def check_stack_canary(self):
        try:
            self.elf.get(lief.ELF.DYNAMIC_TAGS.GNU_STACK)
            return True
        except:
            return False
    def check_nx(self):
        return lief.PE.DLL_CHARACTERISTICS.NX_COMPAT in self.characteristics
    def check_rpath(self):
        try:
            self.elf.get(lief.ELF.DYNAMIC_TAGS.RPATH)
            return True
        except:
            return False
    def checksec(self):
        return {
            'ASLR': self.check_aslr(),
            'DEP': self.check_dll_characteristics(),
            'SEH': self.check_seh(),
            'SafeSEH': self.check_safe_seh(),
            'HighEntropyVA': self.check_high_entropy_va(),
            'ForceIntegrity': self.check_force_integrity(),
            'Relro': self.check_relro(),
            'StackCanary': self.check_stack_canary(),
            'NX': self.check_nx(),
            'RPATH': self.check_rpath()
        }
if __name__ == '__main__':
    save_file = {}
    abs_path = os.path.abspath(__file__)[:os.path.abspath(__file__).rfind('\\')]
    for file in os.listdir():
        if file.endswith('.exe' or '.dll'):
            file_path = os.path.join(abs_path, file)
            print(f"Checking {file_path}...")
            analysis = Checker(file_path)
            results = {
                'file': file,
                'protections': analysis.checksec(),
                'vuln_functions': analysis.check_vuln_functions()
            }
            save_file[file] = results
    with open('results.json', 'w') as f:
        json.dump(save_file, f, indent=4)
    print("Done! Results saved to results.json")
