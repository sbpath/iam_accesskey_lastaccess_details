import boto3
import json

# Create an IAM client
iam = boto3.client('iam')
# Create a CloudTrail client
cloudtrail = boto3.client('cloudtrail')

# Get a list of all IAM users
users_response = iam.list_users()

# Iterate through each user to retrieve access key information
for user in users_response['Users']:
    user_name = user['UserName']

    # Get a list of access keys for the user
    access_keys_response = iam.list_access_keys(UserName=user_name)

    # Iterate through each access key for the user
    for access_key in access_keys_response['AccessKeyMetadata']:
        access_key_id = access_key['AccessKeyId']

        # Get the last accessed timestamp for the access key
        access_key_last_used_response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
        last_used_timestamp = access_key_last_used_response['AccessKeyLastUsed']['LastUsedDate']
        
        # Convert timestamp to a human-readable format
        last_used_date = last_used_timestamp.strftime('%Y-%m-%d %H:%M:%S')

        # Lookup CloudTrail events for the access key
        cloudtrail_events = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'AccessKeyId', 'AttributeValue': access_key_id}
            ]
        )

        # Extract event information from CloudTrail events
        event_info = []
        for event in cloudtrail_events['Events']:
            event_name = event['EventName']
            event_time = event['EventTime']
            event_source = event['EventSource']
            event_data = json.loads(event['CloudTrailEvent'])
            event_sip = event_data.get('sourceIPAddress', 'N/A')

            
            event_info.append(f"Event Name: {event_name}, Event Time: {event_time}, Event Source: {event_source},Event Source IP: {event_sip}")

        # If events were found, print them
        if event_info:
            print(f"====================================================================================")
            print(f"IAM User: {user_name}, Access Key ID: {access_key_id}, Last Used: {last_used_date}")
            print("CloudTrail Events:")
            for info in event_info:
                print(info)
        else:
            print(f"====================================================================================")
            print(f"IAM User: {user_name}, Access Key ID: {access_key_id}, Last Used: {last_used_date}")
            print("No matching CloudTrail events found, please check CloudTrail events retention policy.")


