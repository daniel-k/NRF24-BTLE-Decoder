#!/usr/bin/python3

input = '1490447249.375123, address: DEADBEEF11, length: 32, pid: 1, no_ack: 0, data: 33 11 1D 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ED 2A 00 08 78 0C 00 20 68'

from datetime import datetime
import binascii
import sys

class Packet:
	def __init__(self, string):
		self.raw = string.strip()
		self._parse()

	def _parse(self):
		splitted = self.raw.split(', ')
		self._time = splitted[0]

		for attribute in splitted[1:]:
			# print(attribute)
			name, value = attribute.split(': ')
			setattr(self, '_' + name, value)

		self.time = datetime.fromtimestamp(float(self._time))
		self.data = bytearray.fromhex(self._data)
		try:
			self.address = bytearray.fromhex(self._address)
		except:
			self.address = b'\x00'
			print('cannot parse address ' + self._address)

		self.length = int(self._length)
		self.pid = int(self._pid)
		self.no_ack = bool(int(self._no_ack))

	def __repr__(self):
		return "[{:02x}] 0x{:02x} -> 0x{:02x}: {}".format(
			self.get_type(), self.get_source(),
			self.get_destination(), binascii.hexlify(self.get_payload()))

	def get_source(self):
		return self.data[0]

	def get_destination(self):
		return self.data[1]

	def get_type(self):
		return self.data[2]

	def get_payload(self):
		return self.data[3:]

class PacketR2MAC(Packet):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def get_type(self):
		if super().get_type() == 1:
			return 'Beacon'
		elif super().get_type() == 2:
			return 'AssociationRequest'
		elif super().get_type() == 3:
			return 'Data'
		else:
			return 'Unknown'

	def __repr__(self):
		if self.get_type() == 'Beacon':
			memberCount = self.get_payload()[0]
			members = self.get_payload()[1:1+memberCount]

			return "[Beacon] Coordinator: 0x{:02x}, #members: {}, members: {} [no_ack: {}, dest: {:02x}]".format(
				self.get_source(), memberCount, binascii.hexlify(members),
				self.no_ack, self.get_destination())

		if self.get_type() == 'Data':
			return "[Data] 0x{:02x} -> 0x{:02x}: {}".format(
				self.get_source(), self.get_destination(),
				binascii.hexlify(self.get_payload()))

		if self.get_type() == 'AssociationRequest':
			return "[AssocRequest] 0x{:02x} -> 0x{:02x}".format(
				self.get_source(), self.get_destination())


		return "[Unknown] 0x{:02x} -> 0x{:02x}".format(
			self.get_source(), self.get_destination())

try:
	while True:
		line = sys.stdin.readline()
		p = PacketR2MAC(line)
		print(p)

except KeyboardInterrupt:
	sys.stdout.flush()
	pass
