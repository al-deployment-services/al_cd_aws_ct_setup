Wrapper for AWS Cloudtrail Collection Source setup in Alert Logic (Log Manager)
===============================================================================
This script will setup AWS Cloudtrail log source link in Alert Logic (Log Manager). Two components that will be created:

- New Credentials based on the provided IAM role + external ID 
- New Cloudtrail log source based on the given SQS name

Full manual step by step reference can be found in here: https://docs.alertlogic.com/install/cloud/amazon-web-services-log-manager-direct-linux.htm

Requirements
------------
* Alert Logic Account ID (CID)
* User API Key for Alert Logic Log Manager API
* IAM role for Log Manager (https://docs.alertlogic.com/install/cloud/amazon-web-services-log-manager-direct-linux.htm#createPolicy)
* SQS subscribed to existing Cloudtrail SNS

Deployment Mode
---------------
* ADD = will create the Log Manager AWS Cloudtrail log source
* DEL = will delete the existing Cloudtrail log source

Sample ADD Usage
----------------
Replace the parameters to match your environment and run this command ::

    python cd_aws_ct_setup.py ADD --key USER_API_KEY --cid 10000 --iam arn:aws:iam::052672429986:role/Log_Manager_CloudTrail_Role --ext MY_EXT_ID --cred Cloudtrail_Cred --sqs AlertLogic_LM_CloudTrail_SQS --reg us-east-1 --ct Cloudtrail --dc defender-us-denver

Take note of the output from the script, you will need to record the Cloudtrail source ID if you wish to delete it later using this script (see below)

Sample DEL Usage
----------------
Replace the parameters to match your environment and run this command ::

    python cd_aws_ct_setup.py DEL --key USER_API_KEY --cid 10000 --uid 9563267B-5540-1005-870C-0050568532D4 --dc defender-us-denver

Note

* Deletion of Cloudtrail log source basically will archive the log source, but it never trully remove it (you can still query it via API)

* the Cloudtrail credentials (IAM role) registration will be removed as part of this process


Arguments
----------
  -h, --help   show this help message and exit
  --key KEY    Alert Logic Log Manager user API Key  
  --cid CID    Alert Logic Customer CID as target for this deployment  
  --arn ARN    Cross Account IAM role arn for Log Manager Cloudtrail
  --ext EXT    External ID specified in IAM role trust relationship
  --cred CRED  Credential name, free form label
  --sqs SQS    Name of the SQS that subscribed to Cloudtrail SNS
  --reg REG    AWS region where the is SQS deployed, i.e. us-east-1
  --ct CT      Log source name, free form label
  --uid uid    Cloudtrail log source ID (add this only if you want to delete it)
  --dc DC      Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport


Exit Code
----------
If you going to integrate this script to another orchestration tool, you can use the exit code to detect the status:

* 0 = script run successfully
* 1 = missing or invalid argument
* 2 = environment issue such as invalid SQS arn or invalid API key
* 3 = timeout 

WARNING: This script will not revert back any changes due to timeout, any commands / API calls that it executed prior to timeout will run until completed, even if the script exit due to timeout.

License and Authors
===================
License:
Distributed under the Apache 2.0 license.

Authors: 
Welly Siauw (welly.siauw@alertlogic.com)
