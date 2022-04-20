import gdb

#Twitter: https://twitter.com/kzalloc1
#GitHub: https://github.com/tin-z



###           #
## Constants ##
#           ###

x86_64_convention = "RDI, RSI, RDX, RCX, R8, R9"


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
## utils ##
#       ###

class simpleLogger :
    def append(self, out):
        print(out)

slog = simpleLogger()


def format_string_return(data):
    return ":".join(data.split(":")[1:]).strip()


###         #
## Classes ##
#         ###

class lambdaRule :
    def __init__(self, flambda, fname, desc):
        self.flambda = flambda
        self.fname = fname
        self.desc = desc

    def check(self, args, ret_value):
        self.last_args = args
        self.last_ret_value = ret_value
        return self.flambda(args, ret_value)

    def report(self):
        return WARNING("[!]") + PTR['L'](" Warning") + ": {}\n {}({}) -> {}\n".format(
                self.desc, PTR['H2'](self.fname), ",".join([hex(x) for x in self.last_args]), self.last_ret_value
        )

    def skel_eval_a_lambdaRule(args, ret_value):
        pass


class alertRules :
    def __init__(self) :
        self.rules = {}
    
    def add(self, lambda_rule) :
        fname = lambda_rule.fname
        if fname not in self.rules :
            self.rules[fname] = []
        self.rules[fname].append(lambda_rule)

    def check(self, fname, args=None, ret_value=None) :
        if fname not in self.rules :
            self.rules[fname] = []
        for check_i in self.rules[fname] :
            if check_i.check(args, ret_value) :
                slog.append(check_i.report())


class NetFinishBreakpoint (gdb.FinishBreakpoint):

    def __init__ (self):
        super(NetFinishBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.silent = True 

    def recv(self):
        args = globals()["last_session"][1]
        fd_t, buf_t, len_t, flags_t = args
        ret_value = int(gdb.parse_and_eval("$rax"))
        slog.append(
            PTR['H2']("recv")+"({}, 0x{:x}, {}, {}) -> {}\n \\--> buf:{}\n".format(
                fd_t, buf_t, len_t, flags_t, ret_value ,\
                format_string_return(gdb.execute("x/s 0x{:x}".format(buf_t), to_string=True))
            )
        )
        NetBreakpoint.post_rules.check("recv", args, ret_value)
        return False

    def stop(self):
        self.net_idx = globals()["last_session"][0]
        if self.net_idx == 0 :
            return self.recv()
        else :
            print("#TODO")
        return False


class NetBreakpoint(gdb.Breakpoint):

    pre_rules = alertRules()
    post_rules = alertRules()

    def __init__(self, spec, net_idx):
        super(NetBreakpoint, self).__init__(
            spec, gdb.BP_BREAKPOINT, internal=True
        )
        self.net_idx = net_idx

    def recv(self):
        fd_t = int(gdb.parse_and_eval("$rdi"))
        buf_t = int(gdb.parse_and_eval("$rsi"))
        len_t = int(gdb.parse_and_eval("$rdx"))
        flags_t = int(gdb.parse_and_eval("$rcx"))
        args = [fd_t, buf_t, len_t, flags_t]
        globals()["last_session"] = [self.net_idx, args]
        NetBreakpoint.pre_rules.check("recv", args)
        return False

    def stop(self):
        rets = False
        if self.net_idx == 0 :
            rets = self.recv()
        else :
            print("#TODO")
        NetFinishBreakpoint()
        return rets


###      #
## Main ##
#      ###


#### Set rules ####
def check_pattern(args, ret_value):
  str_now = format_string_return(gdb.execute("x/s 0x{:x}".format(args[1]), to_string=True))
  return "/bin/sh" in str_now or "nib/" in str_now

NetBreakpoint.pre_rules.add(lambdaRule(lambda x, y: x[2] > 4096, "recv", "'len' argument must be less-equal to 4096"))
NetBreakpoint.post_rules.add(lambdaRule(lambda x, y: x[2] != y, "recv", "Number of chars read was less than size initially requested"))
NetBreakpoint.post_rules.add(lambdaRule(check_pattern, "recv", "Suspicious data received '/bin/sh'"))


#### Set socket network breakpoints ####

max_callstack_depth = 16
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
backtrace_limit_command = "set backtrace limit " + str(max_callstack_depth)
gdb.execute(backtrace_limit_command)

NetBreakpoint("recv", 0)
print()

