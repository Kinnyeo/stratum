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

for j in range(1000):
	te = sh.TableEntry("egress.tbl_vlan_egress")(action="strip_vlan")
	te.match["istd.egress_port"] = str(j)
	entries.append(te)

print("Starting timer")
start = time.time()
for entry in entries:
	entry.insert()
	
end = time.time()
dt = end - start
print("time =", dt)
file = open("tests.csv", "a")
file.write("egress.tbl_vlan_egress; " + str(dt).replace('.', ',') + '\n')
file.close()

#csv

for entry in entries:
	entry.delete()

sh.teardown()
