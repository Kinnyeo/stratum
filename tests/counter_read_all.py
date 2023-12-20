import p4runtime_sh.shell as sh
import time

# you can omit the config argument if the switch is already configured with the
# correct P4 dataplane.
sh.setup(
    device_id=1,
    grpc_addr='127.0.0.1:9559',
    election_id=(0, 1), # (high, low)
    #config=sh.FwdPipeConfig('p4info.txt','out.o')
)

entries = []

co = sh.CounterEntry("ingress.in_pkts")
entries.append(co)

print("Starting timer")
start = time.time()
for entry in entries:
	entry.read(lambda c: print(c))
	
end = time.time()
dt = end - start
print("time =", dt)

sh.teardown()
