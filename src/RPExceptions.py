

class RPException(Exception):
	def __init__(self, message):
		self.message = message

	def what(self):
		return message

class EmptyDomain(RPException):
	'''You didn't provide a domain'''
