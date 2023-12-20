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
	te = sh.TableEntry("ingress.tbl_switching")(action="forward")
	te.match["headers.ethernet.dst_addr"] = str(j)
	te.match["headers.vlan_tag.vlan_id"] = "1"
	te.action["output_port"] = "0x6162"
	entries.append(te)

print("Starting timer")
start = time.time()
for entry in entries:
	entry.insert()
	
end = time.time()
dt = end - start
print("time =", dt)
file = open("tests.csv", "a")
file.write("ingress.tbl_switching; " + str(dt).replace('.', ',') + '\n')
file.close()

for entry in entries:
	entry.delete()

sh.teardown()
