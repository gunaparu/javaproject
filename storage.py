import boto3
import csv
import subprocess
import time

# Fetch all configured AWS profiles
def get_aws_profiles():
    try:
        result = subprocess.run(["aws", "configure", "list-profiles"], capture_output=True, text=True)
        return result.stdout.strip().split("\n")
    except Exception as e:
        print(f"Error fetching AWS profiles: {e}")
        return []

# Function to get AWS Account ID
def get_account_id(session):
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except:
        return "Unknown"

# Function to get S3 Storage Size
def get_s3_size(session):
    try:
        s3_client = session.client("s3")
        total_size = 0
        response = s3_client.list_buckets()
        for bucket in response["Buckets"]:
            try:
                metrics = s3_client.get_bucket_metrics_configuration(Bucket=bucket["Name"], Id="EntireBucket")
                total_size += int(metrics["StorageClassAnalysis"]["DataExport"]["S3BucketDestination"]["Bucket"])
            except:
                continue
        return total_size / (1024 ** 3)  # Convert Bytes to GB
    except:
        return 0

# Function to get EBS Storage Size
def get_ebs_size(session):
    try:
        ec2_client = session.client("ec2")
        volumes = ec2_client.describe_volumes()["Volumes"]
        return sum(volume["Size"] for volume in volumes)  # GB
    except:
        return 0

# Function to get RDS Storage Size
def get_rds_size(session):
    try:
        rds_client = session.client("rds")
        instances = rds_client.describe_db_instances()["DBInstances"]
        return sum(instance["AllocatedStorage"] for instance in instances)  # GB
    except:
        return 0

# Function to get DynamoDB Storage Size
def get_dynamodb_size(session):
    try:
        dynamodb_client = session.client("dynamodb")
        tables = dynamodb_client.list_tables()["TableNames"]
        total_size = 0
        for table_name in tables:
            try:
                table_info = dynamodb_client.describe_table(TableName=table_name)
                total_size += table_info["Table"]["TableSizeBytes"]
            except:
                continue
        return total_size / (1024 ** 3)  # Convert Bytes to GB
    except:
        return 0

# Function to get EFS Storage Size
def get_efs_size(session):
    try:
        efs_client = session.client("efs")
        file_systems = efs_client.describe_file_systems()["FileSystems"]
        return sum(fs["SizeInBytes"]["Value"] for fs in file_systems) / (1024 ** 3)  # Convert Bytes to GB
    except:
        return 0

# CSV Output File
csv_filename = "aws_storage_usage.csv"
storage_data = []

# Get all profiles
aws_profiles = get_aws_profiles()

# Loop through each profile
for profile in aws_profiles:
    print(f"\n🔄 Switching to AWS Profile: {profile}")
    
    try:
        session = boto3.Session(profile_name=profile)
        account_id = get_account_id(session)
        
        # Fetch storage sizes
        s3_size = get_s3_size(session)
        ebs_size = get_ebs_size(session)
        rds_size = get_rds_size(session)
        dynamodb_size = get_dynamodb_size(session)
        efs_size = get_efs_size(session)

        # Compute total storage size
        total_size = s3_size + ebs_size + rds_size + dynamodb_size + efs_size

        # Store results
        storage_data.append([
            account_id, profile, s3_size, ebs_size, rds_size, dynamodb_size, efs_size, total_size
        ])

        print(f"✅ Data collected for {profile} (Account {account_id}): {total_size} GB")

    except Exception as e:
        print(f"❌ Error processing profile {profile}: {e}")

    # Avoid hitting AWS API limits
    time.sleep(1)  # Adding delay to prevent throttling

# Save data to CSV
with open(csv_filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["AWS Account ID", "AWS Profile", "S3 (GB)", "EBS (GB)", "RDS (GB)", "DynamoDB (GB)", "EFS (GB)", "Total (GB)"])
    writer.writerows(storage_data)

print(f"\n📊 Storage data collection completed! Report saved as: {csv_filename}")