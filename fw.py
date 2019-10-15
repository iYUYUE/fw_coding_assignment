#!/usr/bin/env python3
import socket
import struct
import csv
import os
import utils

class Node(object):
    def __init__(self, x_mid=None, rules=[], left_node=None, right_node=None):
        self.x_mid = x_mid
        self.sort_by_start = sorted(rules[:], key=lambda r: r.start_ip)
        self.sort_by_end = sorted(rules[:], key=lambda r: r.end_ip, reverse = True)
        self.left = left_node
        self.right = right_node

class Rule(object):
    def __init__(self, start_ip=None, end_ip=None, start_port=None, end_ports=None):
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.start_port = start_port
        self.end_port = end_ports

    def __str__(self):
    	ips = set([str(self.start_ip), str(self.end_ip)])
    	ports = set([str(self.start_port), str(self.end_port)])
    	return str(("-".join(ips), "-".join(ports)))

class Firewall:
	def __init__(self, filepath, tree = True):
		self.tree = tree
		self.rule_dict = {
			"inbound" : {
				"tcp" : [],
				"udp" : []
			},
			"outbound" : {
				"tcp" : [],
				"udp" : []
			}
		}
		file = open(filepath, "r")
		reader = csv.reader(file, delimiter=',')
		for row in reader:
			rule = self.__create_rule(row[3], row[2])
			self.rule_dict[row[0]][row[1]].append(rule)
		
		self.rule_dict["inbound"]["tcp"].sort(key=self.__key)
		self.rule_dict["inbound"]["udp"].sort(key=self.__key)
		self.rule_dict["outbound"]["tcp"].sort(key=self.__key)
		self.rule_dict["outbound"]["udp"].sort(key=self.__key)

		print()
		print("The rules have been loaded.")
		print()
		print("inbound tcp:")
		print(Firewall.__rule_set_str(self.rule_dict["inbound"]["tcp"]))
		print("inbound udp:")
		print(Firewall.__rule_set_str(self.rule_dict["inbound"]["udp"]))
		print("outbound tcp:")
		print(Firewall.__rule_set_str(self.rule_dict["outbound"]["tcp"]))
		print("outbound udp:")
		print(Firewall.__rule_set_str(self.rule_dict["outbound"]["udp"]))

		if tree:
			self.rule_dict["inbound"]["tcp"] = Firewall.__build_ip_tree(self.rule_dict["inbound"]["tcp"])
			self.rule_dict["inbound"]["udp"] = Firewall.__build_ip_tree(self.rule_dict["inbound"]["udp"])
			self.rule_dict["outbound"]["tcp"] = Firewall.__build_ip_tree(self.rule_dict["outbound"]["tcp"])
			self.rule_dict["outbound"]["udp"] = Firewall.__build_ip_tree(self.rule_dict["outbound"]["udp"])

			print()
			print("The rule tree has been built.")
			print()
			print("inbound tcp:")
			Firewall.__print_rule_tree(self.rule_dict["inbound"]["tcp"])
			print("inbound udp:")
			Firewall.__print_rule_tree(self.rule_dict["inbound"]["udp"])
			print("outbound tcp:")
			Firewall.__print_rule_tree(self.rule_dict["outbound"]["tcp"])
			print("outbound udp:")
			Firewall.__print_rule_tree(self.rule_dict["outbound"]["udp"])

	@staticmethod
	def __rule_set_str(rs):
		return str([str(r) for r in rs])

	@staticmethod
	def __print_rule_tree(root):
		utils.printBTree(root,lambda n: ("(%d)" % len(n.sort_by_start), n.left, n.right) )

	@staticmethod
	def __ip2int(addr):
		return struct.unpack("!I", socket.inet_aton(addr))[0]

	@staticmethod
	def __build_ip_tree(sorted_rules):
		if not sorted_rules:
			return None
		
		left_rules, right_rules, node_rules = [], [], []
		mid_rule = sorted_rules[len(sorted_rules) // 2]
		
		for r in sorted_rules:
			if r.end_ip < mid_rule.start_ip:
				left_rules.append(r)
			elif r.start_ip > mid_rule.start_ip:
				right_rules.append(r)
			else:
				node_rules.append(r)

		return Node(mid_rule.start_ip, node_rules, \
			Firewall.__build_ip_tree(left_rules), \
			Firewall.__build_ip_tree(right_rules))

	def __create_rule(self, ip_range, port_range):
		ip_range = [Firewall.__ip2int(p) for p in ip_range.split("-")]
		port_range = [int(p) for p in port_range.split("-")]
		return Rule(ip_range[0], ip_range[-1], port_range[0], port_range[-1])

	def __search_rule_tree(self, node, ip, port):
		# Searching rules at current node
		
		# IP match
		# Only works because we know each ip interval intersects x_mid
		if ip < node.x_mid:
			for r in node.sort_by_start:
				if r.start_ip > ip:
					break
				# port match
				if r.start_port <= port <= r.end_port:
					return True
		else:
			for r in node.sort_by_end:
				if r.end_ip < ip:
					break
				# port match
				if r.start_port <= port <= r.end_port:
					return True

		if ip < node.x_mid and node.left:
			return self.__search_rule_tree(node.left, ip, port)
		elif ip > node.x_mid and node.right:
			return self.__search_rule_tree(node.right, ip, port)

		return False

	def __rule_match(self, rules, ip, port):
		# one by one match
		for r in rules:
			if r.start_ip <= ip <= r.end_ip and r.start_port <= port <= r.end_port:
				return True
		return False

	def __key(self, r):
		# sort rules by start ip and then end ip
		return float(str(r.start_ip)+'.'+str(r.end_ip))

	def accept_packet(self, direction, protocol, port, ip_address):
		if self.tree:
			return self.__search_rule_tree(self.rule_dict[direction][protocol], Firewall.__ip2int(ip_address), port)
		else:
			return self.__rule_match(self.rule_dict[direction][protocol], Firewall.__ip2int(ip_address), port)

# # fw = Firewall("./rules.csv", False)
# fw = Firewall("./rules.csv")

# print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # matches first rule
# #true
# print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) # matches third rule
# #true
# print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")) # matches second rule
# #true
# print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
# #false
# print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
# # false