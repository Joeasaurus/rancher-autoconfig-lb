import os
import boto3
from time import sleep

class ChallengeProxy(object):
	def add_challenge(self, challenge):
		return True
	def remove_challenge(self, challenge):
		return True

class R53Proxy(ChallengeProxy):
	def __init__(self):
		self.r53 = boto3.client('route53')
		self.zone_id = os.environ["AWS_ZONE_ID"]

	def add_challenge(self, challenge, sleep_time = 10, check_limit = 6):
		check_count = 0
		# Wrap it in an array for the case of a single challenge pair.
		#  -- __create_change_batch expects a 2D: [[],[],[]]
		if type(challenge[0]) is str:
			challenge = [challenge]

		#print challenge

		change = self.__create_change_batch(challenge)

		print "Adding challenge, awaiting confirmation..."
		while check_count < check_limit:
			#print change["ChangeInfo"]["Status"]
			if change["ChangeInfo"]["Status"] == 'INSYNC':
				print "Challenge batch INSYNC"
				return True
			else:
				#print "sleeping...."
				sleep(sleep_time)
				check_count += 1
				change = self.r53.get_change(Id=change["ChangeInfo"]["Id"])

		return False

	def remove_challenge(self, challenge):
		record = self.__get_existing_record(challenge[0])
		return record.delete() if record else False

	def __create_change_batch(self, change_pairs):
		cb = {
			'Comment': 'initiated by rancher-autoconfig-lb',
			'Changes': [self.__create_record_set(d,v) for d,v in change_pairs]
		}
		return self.r53.change_resource_record_sets(
		    HostedZoneId = self.zone_id,
		    ChangeBatch = cb
		)

	def __create_record_set(self, domain, value):
		return {
			'Action': 'UPSERT',
			'ResourceRecordSet': {
				'Name': domain,
				'Type': 'TXT',
				'TTL': 30,
				'ResourceRecords': [
					{
						'Value': '"' + value + '"'
					}
				]
			}
		}
