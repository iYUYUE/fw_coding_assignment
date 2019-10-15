#!/usr/bin/env python3
# based on https://github.com/domoritz/random-csv/blob/master/generate_csv.py
import random
import csv
import sys
import socket
import struct
import fw
import time

directions = ["inbound", "outbound"]
protocols = ["tcp", "udp"]
random.seed(42)

def random_ip_interval():
	i = random.randint(1, 0xffffffff)
	if random.choice([True, False]):
		return socket.inet_ntoa(struct.pack('>I', i)) + "-" + socket.inet_ntoa(struct.pack('>I', i+random.randint(1, 256)))
	else:
		return socket.inet_ntoa(struct.pack('>I', i))

def random_port_interval():
	i = random.randint(1, 65535)
	if random.choice([True, False]):
		return str(i)
	else:
		return str(i) + "-" + str(random.randint(i, min(65535, i+100)))

def generate_random_rule_set(filepath, n):
	generators = []
	generators.append(lambda: random.choice(directions))
	generators.append(lambda: random.choice(protocols))
	generators.append(lambda: random_port_interval())
	generators.append(lambda: random_ip_interval())
	with open(filepath, mode='w') as out:
		writer = csv.writer(out)
		for _ in range(n):
			writer.writerow([g() for g in generators])

def generate_random_packet_test(n):
	generators, tests = [], []
	generators.append(lambda: random.choice(directions))
	generators.append(lambda: random.choice(protocols))
	generators.append(lambda: random.randint(1, 65535))
	generators.append(lambda: socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))
	for _ in range(n):
		tests.append([g() for g in generators])
	return tests

num_rules = 10000
num_test = 100000
random_rules = "random_rules.csv"
report = {}

print("randomly generating rules...")
generate_random_rule_set(random_rules, num_rules)
print("randomly generating tests...")
tests = generate_random_packet_test(num_test)

print("normal_fw loading rules...")
start = time.time()
normal_fw = fw.Firewall(random_rules, False)
end = time.time()
report["normal_fw_load_time"] = "%d s" % (end - start)

print("normal_fw testing...")
start = time.time()
normal_fw_res = [normal_fw.accept_packet(t[0], t[1], t[2], t[3]) for t in tests]
end = time.time()
report["normal_fw_test_time"] = "%d s" % (end - start)
report["normal_fw_test_speed"] = "%d q/s" % int(num_test / (end - start))

print("tree_fw loading rules...")
start = time.time()
tree_fw = fw.Firewall(random_rules)
end = time.time()
report["tree_fw_load_time"] = "%d s" % (end - start)

print("tree_fw testing...")
start = time.time()
tree_fw_res = [tree_fw.accept_packet(t[0], t[1], t[2], t[3]) for t in tests]
end = time.time()
report["tree_fw_test_time"] = "%d s" % (end - start)
report["tree_fw_test_speed"] = "%d q/s" % int(num_test / (end - start))

if normal_fw_res == tree_fw_res: 
    print ("The results are identical") 
else : 
    print ("The results are not identical")

for k in report:
	print(k, report[k])