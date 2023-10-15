import yaml
import os.path
import argparse
from unicorn import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *

class SysInfo:
        
    def printDebug(self):
        print(f"Text Segment:\t{hex(self.Addr.text_low)} - {hex(self.Addr.text_high)}")
        print(f"BSS Segment:\t{hex(self.Addr.bss_low)} - {hex(self.Addr.bss_high)}")
        print(f"Stack Segment:\t{hex(self.Addr.stack_low)} - {hex(self.Addr.stack_high)}")

        print(f"Start Address:\t{hex(self.Addr.start)}")
        print(f"End Address:\t{hex(self.Addr.end)}")

        print(f"Architecutre:\t{self.arch}")
        print(f"Bit:\t\t{self.bit}")
        print(f"Endian:\t\t{self.endian}")

    def __init__(self, config_file="config.yaml"):
        with open(config_file, 'r') as file:
            self.config = yaml.safe_load(file)

        self.bin_data   = open(self.config.get('bin_path', None), "rb").read()

        self.Addr       = self.Addresses(self.config, len(self.bin_data))
    
        self.arch       = self.config.get("architecture", None)
        self.bit        = self.config.get("bit", None)
        self.endian     = self.config.get("endian", None)
        self.Reg        = self.Registers(self.arch)

        # Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
        self.mu         = Uc(globals().get(f"UC_ARCH_{self.arch}"), \
                             globals().get(f"UC_MODE_{self.bit}") | 
                                           globals().get(f"UC_MODE_{self.endian}_ENDIAN"))
    class Addresses():

        def align(self, number):
            if number % self.page_size == 0:
                return number
            else:
                # Calculate the next valid page boundary
                aligned_number = ((number // self.page_size) + 1) * self.page_size
                return aligned_number

        def __init__(self, config, bin_len):
            self.page_size  = config.get('page_size', 0x1000)
            self.text_low   = config.get('text_address', None)
            self.text_high  = self.align(self.text_low + bin_len)
            self.bss_low    = config.get("bss_low", self.align(self.text_high))
            self.bss_high   = config.get("bss_high", self.align(self.bss_low + bin_len//2))
            self.stack_low  = config.get("stack_low", self.align(self.bss_high))
            self.stack_high = config.get("stack_high", self.align(self.stack_low + 0x10000000))
            self.stack_cur  = self.align(self.stack_high // self.stack_low + self.stack_low)
            self.start      = config.get("start_address", None)
            self.end        = config.get("end_address", None)


    # reads the architecture specific yaml config to assign 
    class Registers():
        def __init__(self, arch):
            try:
                with open(os.path.join("architectures", arch+".yaml")) as file:
                    self.config = yaml.safe_load(file)
            except:
                print("ERROR: unsupported architecture -> ", arch)
                exit(0)

            self.ra         = globals().get(self.config.get("ra", None))
            self.pc         = globals().get(self.config.get("pc", None))
            self.sp         = globals().get(self.config.get("sp", None))
            self.ret_val    = globals().get(self.config.get("ret_val", None))
            self.ret_val    = globals().get(self.config.get("ret_val", None))

            self.func_args  = [globals().get(reg, None) for reg in self.config.get("func_args", None)]

SI = SysInfo()

def initMemoryMappings():

    # map and write the binary into the text/data segment
    SI.mu.mem_map(SI.Addr.text_low, SI.Addr.text_high - SI.Addr.text_low)
    SI.mu.mem_write(SI.Addr.text_low, SI.bin_data)
    SI.bin_data = None # unsure if this actually helps, but theoretically frees up some memory

    # map the bss segment
    SI.mu.mem_map(SI.Addr.bss_low, SI.Addr.bss_high - SI.Addr.bss_low)

    # map the stack
    SI.mu.mem_map(SI.Addr.stack_low, SI.Addr.stack_high - SI.Addr.stack_low)

def initGlobalVariables():
    pass

def initFunctionArguments():
    pass

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def main(args):
    SI.printDebug()

    initMemoryMappings()
    initGlobalVariables()
    initFunctionArguments()
    
    SI.mu.emu_start(SI.Addr.start, SI.Addr.end)

    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Binary Emulator")
    parser.add_argument('--config', default='/path', help='Path to the config file')
    args = parser.parse_args()
    main(args)

