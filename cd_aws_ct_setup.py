from __future__ import print_function
import os.path, json, requests, logging, datetime, argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#API headers and url
HEADERS = {'content-type': 'application/json'}

def get_api_endpoint(target_dc):
	if target_dc == "defender-us-denver":
		return "https://publicapi.alertlogic.net/api/lm/v1/"
	elif target_dc == "defender-us-ashburn":
		return "https://publicapi.alertlogic.com/api/lm/v1/"
	elif target_dc == "defender-uk-newport":
		return "https://publicapi.alertlogic.co.uk/api/lm/v1/"
	else:
		return False

def get_source_cloudtrail(token, endpoint, target_ct, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/sources/" + target_ct	
	REQUEST = requests.get(API_ENDPOINT, headers=HEADERS, auth=(token,''))
	
	print ("Retrieving Cloudtrail info status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 200:
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["s3aws"] = {}
		RESULT["s3aws"]["id"] = "n/a"
	return RESULT

def del_source_cloudtrail(token, endpoint, target_ct, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/sources/" + target_ct
	REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(token,''))	
	print ("Delete Cloudtrail source status : " + str(REQUEST.status_code), str(REQUEST.reason))

def del_credentials(token, endpoint, target_cred, target_cid):
	API_ENDPOINT = endpoint + target_cid + "/credentials/" + target_cred
	REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(token,''))	
	print ("Delete credentials status : " + str(REQUEST.status_code), str(REQUEST.reason))
	
def post_credentials(token, endpoint, payload, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/credentials/iam_role"
	REQUEST = requests.post(API_ENDPOINT, headers=HEADERS, auth=(token,''), data=payload)

	print ("Create Credentials status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["iam_role"]  = {}
		RESULT["iam_role"]["id"] = "n/a"
	return RESULT

def post_ct_source(token, endpoint, payload, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/sources/s3aws"
	REQUEST = requests.post(API_ENDPOINT, headers=HEADERS, auth=(token,''), data=payload)

	print ("Create Cloudtrail Source Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["s3aws"]  = {}
		RESULT["s3aws"]["id"] = "n/a"
	return RESULT

def prep_credentials(iam_arn, iam_ext_id, cred_name):
	#Setup dictionary for credentials payload
	RESULT = {}
	RESULT["iam_role"]  = {}
	RESULT["iam_role"]["arn"] = str(iam_arn)
	RESULT["iam_role"]["external_id"] = str(iam_ext_id)	
	RESULT["iam_role"]["name"] = str(cred_name)	
	return RESULT

def prep_cloudtrail(cred_id, sqs_name, region, ct_name):
	#Setup dictionary for Cloudtrail payload
	RESULT = {}
	RESULT["s3aws"]  = {}
	RESULT["s3aws"]["name"] = ct_name
	RESULT["s3aws"]["enabled"] = True
	RESULT["s3aws"]["sqs_queue"] = sqs_name
	RESULT["s3aws"]["aws_region"] = region
	RESULT["s3aws"]["credential_id"] = cred_id
	RESULT["s3aws"]["tags"] = []
	return RESULT

#MAIN MODULE
if __name__ == '__main__':
	
	#Prepare parser and argument
	parent_parser = argparse.ArgumentParser()
	subparsers = parent_parser.add_subparsers(help="Select mode", dest="mode")
	
	#Add parser for both ADD and DELETE mode	
	add_parser = subparsers.add_parser("ADD", help="Add CloudTrail collection")
	del_parser = subparsers.add_parser("DEL", help="Delete CloudTrail collection")
	
	#Parser argument for Add scope
	add_parser.add_argument("--key", required=True, help="User Key for Alert Logic Log Manager API Authentication")	
	add_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target")
	add_parser.add_argument("--iam", required=True, help="Cross Account IAM role arn")
	add_parser.add_argument("--ext", required=True, help="External ID specified in IAM role trust relationship")
	add_parser.add_argument("--cred", required=True, help="Credential name, free form label, not visible in Alert Logic UI")
	add_parser.add_argument("--sqs", required=True, help="SQS Name that subscribe to CloudTrail SNS")
	add_parser.add_argument("--reg", required=True, help="Region where the SQS created")
	add_parser.add_argument("--ct", required=True, help="Name label for this Cloudtrail source")
	add_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")

	#Parser argument for Delete scope
	del_parser.add_argument("--key", required=True, help="User Key for Alert Logic Log Manager API Authentication")	
	del_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target")	
	del_parser.add_argument("--uid", required=True, help="Cloudtrail source ID that you wish to delete")
	del_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")

	#Parser argument for Delete environment
	
	args = parent_parser.parse_args()

	#Set argument to variables
	if args.mode == "ADD":
		print ("\n### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = ADD ###\n")

		APIKEY = args.key		
		TARGET_CID = args.cid		
		TARGET_IAM_ROLE_ARN = args.iam
		TARGET_EXT_ID = args.ext
		TARGET_CRED_NAME = args.cred
		TARGET_SQS_NAME = args.sqs
		TARGET_SQS_REGION = args.reg
		TARGET_CT_NAME = args.ct
		TARGET_DEFENDER = args.dc

		#get API endpoint
		ALERT_LOGIC_LM = get_api_endpoint(TARGET_DEFENDER)

		if ALERT_LOGIC_LM != False:
			print ("### Creating IAM Role Link ###")
			#Create credentials using the IAM role ARN and external ID	
			CRED_PAYLOAD = prep_credentials(TARGET_IAM_ROLE_ARN, TARGET_EXT_ID, TARGET_CRED_NAME)			
			CRED_RESULT = post_credentials(APIKEY, ALERT_LOGIC_LM, str(json.dumps(CRED_PAYLOAD, indent=4)), TARGET_CID)
			CRED_ID = str(CRED_RESULT["iam_role"]["id"])

			if CRED_ID != "n/a":
				print ("Cred ID : " + CRED_ID)
				print ("### Creating Cloud Trail Link ###")
				CT_PAYLOAD = prep_cloudtrail(CRED_ID, TARGET_SQS_NAME, TARGET_SQS_REGION, TARGET_CT_NAME)
				CT_RESULT = post_ct_source(APIKEY, ALERT_LOGIC_LM, str(json.dumps(CT_PAYLOAD, indent=4)), TARGET_CID)
				CT_ID = str(CT_RESULT["s3aws"]["id"])

				if CT_ID != "n/a":
					print ("Cloudtrail Source ID : " + CT_ID)
				else:
					print ("### Failed to create Cloudtrail source, see response code + reason above, stopping .. ###")	

			else:
				print ("### Failed to create credentials, see response code + reason above, stopping .. ###")

		else:
			print ("Invalid data center assignment, use -h for more details, stopping ...")

	elif args.mode == "DEL":
		print ("\n### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = DELETE ###\n")

		APIKEY = args.key		
		TARGET_CID = args.cid				
		TARGET_CT_ID = args.uid
		TARGET_DEFENDER = args.dc

		#get API endpoint
		ALERT_LOGIC_LM = get_api_endpoint(TARGET_DEFENDER)

		CT_RESULT = get_source_cloudtrail(APIKEY, ALERT_LOGIC_LM, TARGET_CT_ID, TARGET_CID)
		if CT_RESULT["s3aws"]["id"] != "n/a":
			#Get the credentials ID
			CRED_ID = CT_RESULT["s3aws"]["credential_id"]

			#Delete the cloudtrail source
			del_source_cloudtrail(APIKEY, ALERT_LOGIC_LM, TARGET_CT_ID, TARGET_CID)

			#Delete the credentials
			del_credentials(APIKEY, ALERT_LOGIC_LM, CRED_ID, TARGET_CID)

		else:
			print ("Failed to find the Cloudtrail source ID, see response code + reason above, stopping ..")


	print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")	