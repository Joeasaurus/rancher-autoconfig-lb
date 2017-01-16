class LEException(Exception):
	def __init__(self, message):
		self.message = message

	def what(self):
		return message

class EmptyDomain(LEException):
	'''You didn't provide a domain'''
