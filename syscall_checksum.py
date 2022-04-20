import gdb
import sys
from hashlib import sha256

sys.path.append(".")

import r2pipe


#Twitter: https://twitter.com/kzalloc1
#GitHub: https://github.com/tin-z



###                        #
## Configurable variables ##
#                        ###

vmlinux_path = "vmlinux"
systemmap_path = "System.map"
output_file = "syscall_hashes.csv"
ia32_output_file = "ia32_syscall_hashes.csv"

DBG=1
VERBOSE=0


###         #
## Colours ##
#         ###

EC = '\x1b[0m'
BOLD = '\x1b[1m'
INIT = {'f':30,'b':40,'hf':90,'hb':100}
COLORS = ("BLACK",0),("RED",1),("GREEN",2),("YELLOW",3),("BLUE",4),("CYAN",6)
for x,y in COLORS :
  globals()[x] = {k:"\x1b[{}m".format(v+y) for k,v in INIT.items()}

FAIL = lambda x : BOLD + RED['f'] + x + EC
WARNING = lambda x : BOLD + YELLOW['b'] + BLACK['f'] + x + EC
PTR = {"H":lambda x : BLUE['f'] + x + EC, "S": lambda x : YELLOW['hf'] + x + EC, "L" : lambda x : RED['f'] + x + EC }
PTR.update( { "HEAP":PTR["H"], "STACK":PTR["S"], "LIBC":PTR["L"] } )
PTR.update( { "H1":lambda x : BLUE['hf'] + x + EC, "H2":lambda x : CYAN['f'] + x + EC, "H3":lambda x : CYAN['hf'] + x + EC })
PTR.update( { "F1":lambda x : BOLD + RED['f'] + BLACK['b'] + "|{}|".format(x) + EC } )
PTR.update( { "F2":lambda x : BOLD + GREEN['f'] + BLACK['b'] + "|{}|".format(x) + EC } )


###       #
## Utils ##
#       ###

def format_string_return(data):
  output = []
  for x in data.split("\n")[:-1] :
    for y in x.split(":")[1].split("0x")[1:] :
      output.append(y.strip())
  return "".join(output)


def do_sha256(data):
  sha_tmp = sha256()
  sha_tmp.update(data)
  return sha_tmp.hexdigest()


###         #
## Classes ##
#         ###

class Sym_kernel :

  def __init__(self, addr, label, sym) :
    self.sym = sym
    self.addr = addr
    self.label = label

  def __repr__(self):
    return "{}({})".format(self.__class__.__name__, self.__str__())

  def __str__(self):
    return "0x{:x}, {}, {})".format(self.addr, self.label, self.sym)


class Sym_kernel_static(Sym_kernel) :

  def parse_systemmap(sysmap):
    func_name = sys._getframe().f_code.co_name
    hm_addr = {}
    hm_sym = {}
    with open(sysmap, "r") as fp :
      lines = fp.readlines()
      for x in lines :
        addr, label, sym = x.strip().split(" ")
        sym_now = Sym_kernel_static(int(addr,16), label, sym)

        if VERBOSE :
          print("{}: parse entry: {}".format(func_name, sym_now))

        if sym_now.addr not in hm_addr :
          hm_addr[sym_now.addr] = []
        hm_addr[sym_now.addr].append(sym_now)

        if sym_now.sym not in hm_sym :
          hm_sym[sym_now.sym] = []
        hm_sym[sym_now.sym].append(sym_now)

    return  (hm_addr, hm_sym)


class Sym_kernel_dyn(Sym_kernel) :

  def parse_dyn_symtable(addr, size, entry_size=8):
    dyn_symtab = []
    for i in range(0, (size*entry_size), entry_size) :
      dyn_symtab.append( Sym_kernel_dyn(
          int(gdb.parse_and_eval("(unsigned long long) *(unsigned long long *)({})".format(hex(addr+i))))) 
      )
    return dyn_symtab

  def __init__(self, addr, label=None, sym=None) :
    super().__init__(addr, label, sym)


class r2Ctf(r2pipe.open_sync.open):
   
  def __init__(self, binary_name):
    if DBG :
      print("Creating object r2Ctf(\"{}\"), it takes usually 1-2 minutes because of kernel binary size".format(binary_name))
    super(r2Ctf,self).__init__(binary_name)
    self.binary_name = binary_name
    self.__init_obj()
  
  def __init_obj(self):
    self.cmd('aa')
  
  def adjust_basic_block(self, systab_entry):
    self.cmd("s 0x{:x}".format(systab_entry.addr))
    rets = self.cmdj("pdbj")
    systab_entry.bb_static = bytes.fromhex("".join([ x['bytes'] for x in rets]))
    systab_entry.bb_length = len(systab_entry.bb_static)
  
  def __str__(self):
    return  "Binary: {}\n".format(self.binary_name)


sym_addr_lookup, sym_lookup  = Sym_kernel_static.parse_systemmap(systemmap_path)
vmlinux_analysis = r2Ctf(vmlinux_path)



###      #
## Main ##
#      ###

print("\n### Check 2: Do syscall code integrity: hash the code segment of each syscall using sha256 (only for 1st basic block area)")

systab_addr = int(gdb.parse_and_eval("(unsigned long long) sys_call_table"))
systab_size = int(int(str(gdb.parse_and_eval("(unsigned long long) sizeof(sys_call_table)")).strip(), 16) / 8)
systab_entries = Sym_kernel_dyn.parse_dyn_symtable(systab_addr, systab_size)

systab32_addr = int(gdb.parse_and_eval("(unsigned long long) ia32_sys_call_table"))
systab32_size = int(int(str(gdb.parse_and_eval("(unsigned long long) sizeof(ia32_sys_call_table)")).strip(), 16) / 8)
systab32_entries = Sym_kernel_dyn.parse_dyn_symtable(systab32_addr, systab32_size)


def hash_syscall(baddr, entries, entry_size=8):
  ret = True
  for i, x in enumerate(entries) :
    tmp_obj = [ x for x in sym_addr_lookup[x.addr] if "_sys_" in x.sym ][0]
    x.sym = tmp_obj.sym
    x.label = tmp_obj.label

    vmlinux_analysis.adjust_basic_block(x)

    x.bb_dynamic = bytes.fromhex( 
      format_string_return(
        gdb.execute("x/{}bx 0x{:x}".format(x.bb_length, x.addr), to_string=True)
      )
    )

    x.bb_static_checksum = do_sha256(x.bb_static)
    x.bb_dynamic_checksum = do_sha256(x.bb_dynamic)

    if x.bb_static_checksum != x.bb_dynamic_checksum :
      ret = False
      if DBG :
        print("[!] Warning: Unmatch checksums found at syscall '{}' address: 0x{:x}".format(x.sym, x.addr))
        print(" \--> kernel running sha256: {}".format(x.bb_dynamic_checksum))
        print(" \--> vmlinux image  sha256: {}".format(x.bb_static_checksum))
    break

  return ret


print("     - Detect syscall code segment modification ... {}".format(
    PTR['F2']("Passed") if hash_syscall(systab_addr, systab_entries) 
    else PTR['F1']("Failed"))
)

print("     - Detect ia32 syscall code segment modification ... {}".format(
    PTR['F2']("Passed") if hash_syscall(systab32_addr, systab32_entries) 
    else PTR['F1']("Failed"))
)


print("### Check 2: [Done]\n")

