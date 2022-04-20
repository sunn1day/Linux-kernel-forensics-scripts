import gdb
import sys

#Twitter: https://twitter.com/kzalloc1
#GitHub: https://github.com/tin-z



###                        #
## Configurable variables ##
#                        ###

vmlinux_path = "vmlinux"
systemmap_path = "System.map"

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


sym_addr_lookup, sym_lookup  = Sym_kernel_static.parse_systemmap(systemmap_path)


###      #
## Main ##
#      ###

print("\n### Check 1: Syscall table integrity check")

systab_addr = int(gdb.parse_and_eval("(unsigned long long) sys_call_table"))
systab_size = int(int(str(gdb.parse_and_eval("(unsigned long long) sizeof(sys_call_table)")).strip(), 16) / 8)
systab_entries = Sym_kernel_dyn.parse_dyn_symtable(systab_addr, systab_size)

systab32_addr = int(gdb.parse_and_eval("(unsigned long long) ia32_sys_call_table"))
systab32_size = int(int(str(gdb.parse_and_eval("(unsigned long long) sizeof(ia32_sys_call_table)")).strip(), 16) / 8)
systab32_entries = Sym_kernel_dyn.parse_dyn_symtable(systab32_addr, systab32_size)


def integrity_check_systab(baddr, entries, entry_size=8):
  ret = True
  for i, x in enumerate(entries) :
    if x.addr not in sym_addr_lookup :
      ret = False
      if DBG :
        print("[!] Warning: Invalid entry found at address: 0x{:x}, with value: 0x{:x}".format(baddr + (i*8), x.addr))
    else :
      tmp_obj = [ x for x in sym_addr_lookup[x.addr] if "_sys_" in x.sym ][0]
      entries[i].sym = tmp_obj.sym
      entries[i].label = tmp_obj.label
  return ret


print("     - Detect sys_call_table modification ... {}".format(
    PTR['F2']("Passed") if integrity_check_systab(systab_addr, systab_entries) 
    else PTR['F1']("Failed"))
)

print("     - Detect ia32_sys_call_table modification ... {}".format(
    PTR['F2']("Passed") if integrity_check_systab(systab32_addr, systab32_entries) 
    else PTR['F1']("Failed"))
)

print("### Check 1: [Done]\n")

