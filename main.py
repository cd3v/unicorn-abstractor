import yaml
import struct
import os.path
from unicorn import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *


# TODO: if a instruction crashes, read what it is and print out the instruction as well as values
# of any registers/pointers it is using

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

    def printRegisters(self):
            print("\t\tra: 0x%08x\tpc: 0x%08x\tsp: 0x%08x" % (self.mu.reg_read(self.Reg.ra), 
                                                              self.mu.reg_read(self.Reg.pc), 
                                                              self.mu.reg_read(self.Reg.sp)))
            print("\t\t", end='')
            for i in range(len(self.Reg.func_args)):
                if i > 0 and i % 3 == 0:
                    print("\n\t\t", end='')
                print(f"a{i}: 0x%08x\t" % self.mu.reg_read(self.Reg.func_args[i]), end='')
            print("\n\t\treturn value: 0x%08x\t" % self.mu.reg_read(self.Reg.ret_val))

    def __init__(self, config_file="config.yaml"):
        # TODO: correct this read line to allow for multii document read
        with open(config_file, 'r') as file:
            self.config_all = yaml.safe_load(file)
        
        self.config_sys         = self.config_all["MainSettings"]
        self.config_func_args   = self.config_all["FunctionArgs"]
        self.config_globals     = self.config_all["GlobalVariables"]

        self.bin_data   = open(self.config_sys.get('bin_path', None), "rb").read()

        self.Addr       = self.Addresses(self.config_sys, len(self.bin_data))
    
        self.arch       = self.config_sys.get("architecture", None)
        self.bit        = self.config_sys.get("bit", None)
        self.endian     = self.config_sys.get("endian", None)
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
            self.page_size  = config.get('page_size') or 0x1000
            self.text_low   = config.get('text_address') or None
            self.text_high  = self.align(self.text_low + bin_len)
            self.bss_low    = config.get("bss_low") or self.align(self.text_high)
            self.bss_high   = config.get("bss_high") or self.align(self.bss_low + bin_len//2)
            self.stack_low  = config.get("stack_low") or self.align(self.bss_high)
            self.stack_high = config.get("stack_high") or self.align(self.stack_low + 0x10000000)
            self.stack_cur  = self.align(self.stack_high // self.stack_low + self.stack_low)
            self.start      = config.get("start_address") or None
            self.end        = config.get("end_address") or None


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

            self.func_args  = [globals().get(reg, None) for reg in self.config.get("func_args", None)]

SI = SysInfo()

# maps the different segments into memory and writes the binary into the text segment
def initMemoryMappings():

    # map and write the binary into the text/data segment
    SI.mu.mem_map(SI.Addr.text_low, SI.Addr.text_high - SI.Addr.text_low)
    SI.mu.mem_write(SI.Addr.text_low, SI.bin_data)
    SI.bin_data = None # unsure if this actually helps, but theoretically frees up some memory

    # map the bss segment
    SI.mu.mem_map(SI.Addr.bss_low, SI.Addr.bss_high - SI.Addr.bss_low)

    # map the stack
    SI.mu.mem_map(SI.Addr.stack_low, SI.Addr.stack_high - SI.Addr.stack_low)

# writes our now mapped stack pointer into the sp register and assigns pc
def initRegisterValues():
    SI.mu.reg_write(SI.Reg.pc, SI.Addr.start)
    SI.mu.reg_write(SI.Reg.sp, SI.Addr.stack_cur)

    # TODO: maybe delete this line
    SI.mu.reg_write(SI.Reg.ret_val, 0) # zero out the return address

def initGlobalVariables():
    if not SI.config_globals:
        return

# TODO: currently only supports a single pointer, and array of strings for example would break
def initFunctionArguments():
    if not SI.config_func_args:
        return
    # TODO: distinguish between vars that must be a pointer to a value and ones that are literal
    for i in range(min(len(SI.Reg.func_args), len(SI.config_func_args))):
        curArg = SI.config_func_args[i]
        if curArg['type'] == 'literal':
            SI.mu.reg_write(SI.Reg.func_args[i], SI.config_func_args[i]['value'])
        else:
            #TODO: call a function 'mypack' that automatically packs based off of endianess and bit size
            SI.mu.mem_write(SI.mu.reg_read(SI.Reg.sp), struct.pack('<i',curArg['value']))
            SI.mu.reg_write(SI.Reg.func_args[i], SI.mu.reg_read(SI.Reg.sp))

            # TODO: decide if I need to decrement SI.Reg.sp by SI.bit / 8 after each write to it
     # TODO: if more args are pass than what goes into registers, automatically place on stack

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print("\t>>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    SI.printRegisters()


def main():
    SI.printDebug()

    initMemoryMappings()
    initRegisterValues()
    initGlobalVariables()
    initFunctionArguments()
    
    SI.mu.hook_add(UC_HOOK_CODE, hook_code)
    # SI.mu.hook_add(UC_HOOK_BLOCK, hook_block)
    SI.mu.emu_start(SI.Addr.start, SI.Addr.end)

    # prints the return address
    print(SI.mu.reg_read(SI.Reg.ret_val))

if __name__ == "__main__":
    main()

