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
























import boto3
import csv
import openpyxl
from botocore.exceptions import ClientError
import botocore
import json

def main():
    sts_client = boto3.client('sts')
    with open("finalreport_51to103.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Role Name", "Policy Name", "S3 Allow", "S3 Deny", "ec2_allow", "ec2_deny","IAM Allow","IAM Deny","Cloudtrail Allow","Cloudtrail Deny","RDS Allow","RDS Deny","DynamoDB Allow","DynamoDB Deny","Administrator Access", "AccountNum","Role ARN","Compliance/NonCompliance"])
        root_acc = get_root_account(sts_client)
        print(root_acc)
        assumerole_iam(sts_client, writer)

def get_root_account(client):
    root_acc = client.get_caller_identity().get('Account')
    return root_acc

def assumerole_iam(sts_client, writer):
    MainRole = "Main IAM role to Switch"
    assumed_role_object = sts_client.assume_role(RoleArn=MainRole",RoleSessionName="IAM AssumeRole")
    credentials=assumed_role_object['Credentials']
    iam_client=boto3.client('iam',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
    sts_clientroot1=boto3.client('sts',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
    root_acc = sts_clientroot1.get_caller_identity()
    print(root_acc)
    fname = 'roles-dev.xlsx'
    wb = openpyxl.load_workbook(fname)
    sheet = wb.get_sheet_by_name('Sheet1')
    for rowOfCellObjects in sheet['A1':'A50']:
      try:
        for cellObj in rowOfCellObjects:
          #print(cellObj.coordinate, cellObj.value)
          v1 = cellObj.value
          assumed_role_object = sts_clientroot1.assume_role(RoleArn=v1,RoleSessionName="AssumeRoleSession1")
          credentials=assumed_role_object['Credentials']
          iam_client=boto3.client('iam',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
          sts_client1=boto3.client('sts',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
          account_num = sts_client1.get_caller_identity().get('Account')
          #acc_name =   boto3.client('organizations').describe_account(AccountId=account_num).get('Account').get('Name')
          users = iam_client.list_users()["Users"]
          print("Switching to",account_num)
          iam_roles(iam_client,writer,account_num)
      except botocore.exceptions.ClientError as error: 
        print(error)
        continue
def iam_roles(iam_client, writer, account_num):
    try:
        # S3
        s3_perms_allow = ['s3:*',"s3:CreateBucket","s3:CreateAccessPoint","s3:CreateAccessGrant","s3:CreateAccessPointForObjectLambda","s3:DeleteBucket","s3:DeleteBucketWebsite","s3:DeleteAccessPoint","s3:DeleteAccessGrant","s3:DeleteObject","s3:Create*","s3:Delete*"]
        s3_perms_deny = ["s3:CreateBucket","s3:CreateAccessPoint","s3:CreateAccessGrant","s3:CreateAccessPointForObjectLambda","s3:DeleteBucket","s3:DeleteBucketWebsite","s3:DeleteAccessPoint","s3:DeleteAccessGrant","s3:DeleteObject","s3:Create*","s3:Delete*"]
        # EC2
        ec2_perms_allow = ['ec2:*',"ec2:CreateInternetGateway","ec2:DeleteInternetGateway","ec2:AttachInternetGateway","ec2:CreateNatGateway","ec2:DeleteNatGateway","ec2:CreateVpcPeeringConnection","ec2:CreateNetworkAcl","ec2:DeleteNetworkAcl","ec2:DisassociateNatGatewayAddress","ec2:DisassociateRouteTable","ec2:DisassociateSubnetCidrBlock","ec2:DisassociateVpcCidrBlock","ec2:AuthorizeClientVpnIngress","ec2:AcceptTransitGatewayPeeringAttachment","ec2:AcceptTransitGatewayVpcAttachment","ec2:ModifySubnetAttribute","ec2:ModifyTransitGatewayVpcAttachment","ec2:CreateSubnet","ec2:AcceptVpcPeeringConnection","ec2:DeleteVpcPeeringConnection","ec2:CreateVpc","ec2:DeleteVpc","ec2:ModifyVpcTenancy","ec2:CreateFlowLogs","ec2:DeleteFlowLogs","ec2:AttachVpnGateway","ec2:CreateVpnGateway","ec2:DeleteVpnGateway","ec2:DisableVgwRoutePropagation","ec2:EnableVgwRoutePropagation","ec2:CreateVpnConnectionRoute","ec2:DeleteVpnConnection","ec2:DeleteVpnConnectionRoute","ec2:ModifyVpnConnection","ec2:CreateCustomerGateway","ec2:DeleteCustomerGateway","ec2:CreateRouteTable","ec2:AssociateRouteTable","ec2:CreateRoute","ec2:DeleteRouteTable","ec2:ModifyVpcAttribute","ec2:ReplaceRoute","ec2:DeleteRoute","ec2:CreateTransitGateway","ec2:DeleteTransitGatewayRouteTable","ec2:CreateTransitGatewayRouteTable","ec2:ReplaceTransitGatewayRoute"]
        ec2_perms_deny = ["ec2:CreateInternetGateway","ec2:DeleteInternetGateway","ec2:AttachInternetGateway","ec2:CreateNatGateway","ec2:DeleteNatGateway","ec2:CreateVpcPeeringConnection","ec2:CreateNetworkAcl","ec2:DeleteNetworkAcl","ec2:DisassociateNatGatewayAddress","ec2:DisassociateRouteTable","ec2:DisassociateSubnetCidrBlock","ec2:DisassociateVpcCidrBlock","ec2:AuthorizeClientVpnIngress","ec2:AcceptTransitGatewayPeeringAttachment","ec2:AcceptTransitGatewayVpcAttachment","ec2:ModifySubnetAttribute","ec2:ModifyTransitGatewayVpcAttachment","ec2:CreateSubnet","ec2:AcceptVpcPeeringConnection","ec2:DeleteVpcPeeringConnection","ec2:CreateVpc","ec2:DeleteVpc","ec2:ModifyVpcTenancy","ec2:CreateFlowLogs","ec2:DeleteFlowLogs","ec2:AttachVpnGateway","ec2:CreateVpnGateway","ec2:DeleteVpnGateway","ec2:DisableVgwRoutePropagation","ec2:EnableVgwRoutePropagation","ec2:CreateVpnConnectionRoute","ec2:DeleteVpnConnection","ec2:DeleteVpnConnectionRoute","ec2:ModifyVpnConnection","ec2:CreateCustomerGateway","ec2:DeleteCustomerGateway","ec2:CreateRouteTable","ec2:AssociateRouteTable","ec2:CreateRoute","ec2:DeleteRouteTable","ec2:ModifyVpcAttribute","ec2:ReplaceRoute","ec2:DeleteRoute","ec2:CreateTransitGateway","ec2:DeleteTransitGatewayRouteTable","ec2:CreateTransitGatewayRouteTable","ec2:ReplaceTransitGatewayRoute"]
        #IAM
        iam_perms_allow = ['iam:*',"iam:CreateAccessKey","iam:CreateRole","iam:CreateUser","iam:DeleteAccessKey","iam:DeleteGroup","iam:DeleteRole","iam:DeleteUser"]
        iam_perms_deny = ["iam:CreateUser","iam:DeleteUser","iam:UpdateUser","iam:CreateRole","iam:DeleteRole","iam:PassRole","iam:UpdateRole"]
        # Cloudtrail
        cloudtrail_perms_allow =["cloudtrail:*","cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"]
        cloudtrail_perms_deny = ["cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"]
        # RDS
        rds_perms_allow = ['rds:*',"rds:CreateDBInstance","rds:CreateDBClusterSnapshot","rds:CreateDBCluster","rds:CreateDBSecurityGroup","rds:DeleteDBCluster","rds:DeleteDBInstance","rds:DeleteDBSecurityGroup","elasticfilesystem:Create*","elasticfilesystem:Delete*"]
        rds_perms_deny = ["rds:CreateDBInstance","rds:CreateDBClusterSnapshot","rds:CreateDBCluster","rds:CreateDBSecurityGroup","rds:DeleteDBCluster","rds:DeleteDBInstance","rds:DeleteDBSecurityGroup","elasticfilesystem:Create*","elasticfilesystem:Delete*"]
        # DynamoDB
        dynamodb_perms_allow = ['dynamodb:*',"dynamodb:CreateBackup","dynamodb:CreateGlobalTable","dynamodb:CreateTable","dynamodb:CreateTableReplica","dynamodb:DeleteBackup","dynamodb:DeleteItem","dynamodb:DeleteTable","dynamodb:DeleteTableReplica","dynamodb:DeleteResourcePolicy","dynamodb:PartiQLDelete","dynamodb:Create*","dynamodb:Delete*"]
        dynamodb_perms_deny = ["dynamodb:CreateBackup","dynamodb:CreateGlobalTable","dynamodb:CreateTable","dynamodb:CreateTableReplica","dynamodb:DeleteBackup","dynamodb:DeleteItem","dynamodb:DeleteTable","dynamodb:DeleteTableReplica","dynamodb:DeleteResourcePolicy","dynamodb:PartiQLDelete","dynamodb:Create*","dynamodb:Delete*"]
        # Admin
        admin_access = ['*']
        role_names =['rds-monitoring-role','CloudabilityRole','WizAccess-Role','Okta-Idp-cross-account-role','stacksets-exec-c1c1b0535f75d712e3199a0026442703','CloudWatch-CrossAccountSharingRole']
        CMRrole=account_num+"-cloud-management-Role"
        role_names.append(CMRrole)
        superadminrole = account_num+"-superadminrole-Admin-Role"
        role_names.append(superadminrole)
        adminrole = account_num+"-Admin-Role"
        role_names.append(adminrole)
\
        #print(role_names)
        okta ="Okta"
        AppCore = "AppCore"
        Application = "Application"
        AWSServiceroles="AWSServiceRoleFor"
        paginator = iam_client.get_paginator("list_roles")
        for response in paginator.paginate(PaginationConfig={'MaxItems': 1000}):
            for role in response['Roles']:
                role_name = role["RoleName"]
                assume_doc = role['AssumeRolePolicyDocument']
                assume_string = json.dumps(assume_doc)
                if okta in assume_string:
                  if role_name in role_names:
                    print("Role is core/service",role_name)
                  else:
                    role_arn = role['Arn']
                    attached_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                    policies_list = []
                    s3_allow_list = []
                    s3_deny_list = []
                    ec2_allow_list = []
                    ec2_deny_list = []
                    iam_allow_list = []
                    iam_deny_list = []
                    cloudtrail_allow_list = []
                    cloudtrail_deny_list = []
                    rds_allow_list = []
                    rds_deny_list = []
                    dynamodb_allow_list = []
                    dynamodb_deny_list = []
                    admin_list = []
                    compliance = " Compliance Role"
                    noncompliance = "NonCompliance Role"

                    for policy in attached_policies:
                        #policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
                        policy_document = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                        #print(policy)
                        policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'],VersionId=policy_document)['PolicyVersion']['Document']
                        process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list)
                        policies_list.append(policy['PolicyName'])
                        if policy['PolicyName'] == 'AdministratorAccess':
                          admin_list.append("admin_access")

                    inline_policies = iam_client.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
                    for policy_name in inline_policies:
                        policy_version = iam_client.get_role_policy(RoleName=role['RoleName'], PolicyName=policy_name)['PolicyDocument']
                        process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list)
                        policies_list.append(policy_name)
                    total_allow = s3_allow_list + ec2_allow_list + iam_allow_list + cloudtrail_allow_list + rds_allow_list + dynamodb_allow_list + admin_list

                    if (s3_allow_list and not s3_deny_list) or (ec2_allow_list and not ec2_deny_list) or (iam_allow_list and not iam_deny_list) or (cloudtrail_allow_list and not cloudtrail_deny_list) or (rds_allow_list and not rds_deny_list) or (dynamodb_allow_list and not dynamodb_deny_list) or admin_list:
                      writer.writerow([role_name, ','.join(map(str,policies_list)), ','.join(map(str,set(s3_allow_list))), ','.join(map(str,set(s3_deny_list))), ','.join(map(str,set(ec2_allow_list))), ','.join(map(str,set(ec2_deny_list))),','.join(map(str,set(iam_allow_list))),','.join(map(str,set(iam_deny_list))),','.join(map(str,set(cloudtrail_allow_list))), ','.join(map(str,set(cloudtrail_deny_list))), ','.join(map(str,set(rds_allow_list))), ','.join(map(str,set(rds_deny_list))),','.join(map(str,set(dynamodb_allow_list))), ','.join(map(str,set(dynamodb_deny_list))),','.join(map(str,set(admin_list))), account_num,role_arn,AppCore, noncompliance])
                      print(role_name, f"{AppCore}noncompliance ---->", policies_list, s3_allow_list, s3_deny_list, ec2_allow_list, ec2_deny_list, admin_list, account_num)

                    else:
                      writer.writerow([role_name, ','.join(map(str,policies_list)), ','.join(map(str,set(s3_allow_list))), ','.join(map(str,set(s3_deny_list))), ','.join(map(str,set(ec2_allow_list))), ','.join(map(str,set(ec2_deny_list))),','.join(map(str,set(iam_allow_list))),','.join(map(str,set(iam_deny_list))),','.join(map(str,set(cloudtrail_allow_list))), ','.join(map(str,set(cloudtrail_deny_list))), ','.join(map(str,set(rds_allow_list))), ','.join(map(str,set(rds_deny_list))),','.join(map(str,set(dynamodb_allow_list))), ','.join(map(str,set(dynamodb_deny_list))),','.join(map(str,set(admin_list))), account_num,role_arn, AppCore, compliance])
                      print(role_name, f"{AppCore}compliance ---->", policies_list, s3_allow_list, s3_deny_list, ec2_allow_list, ec2_deny_list, admin_list, account_num)
                elif AWSServiceroles in role_name:
                    if role_name in role_names:
                        print("Role is core/service",role_name)
                    else:
                        role_arn = role['Arn']
                        attached_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                        policies_list = []
                        s3_allow_list = []
                        s3_deny_list = []
                        ec2_allow_list = []
                        ec2_deny_list = []
                        iam_allow_list = []
                        iam_deny_list = []
                        cloudtrail_allow_list = []
                        cloudtrail_deny_list = []
                        rds_allow_list = []
                        rds_deny_list = []
                        dynamodb_allow_list = []
                        dynamodb_deny_list = []
                        admin_list = []
                        compliance = " Compliance Role"
                        noncompliance = "NonCompliance Role"

                        for policy in attached_policies:
                            #policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
                            policy_document = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                            #print(policy)
                            policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'],VersionId=policy_document)['PolicyVersion']['Document']
                            process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list)
                            policies_list.append(policy['PolicyName'])
                            if policy['PolicyName'] == 'AdministratorAccess':
                                admin_list.append("admin_access")

                        inline_policies = iam_client.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
                        for policy_name in inline_policies:
                            policy_version = iam_client.get_role_policy(RoleName=role['RoleName'], PolicyName=policy_name)['PolicyDocument']
                            process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list)
                            policies_list.append(policy_name)
                        total_allow = s3_allow_list + ec2_allow_list + iam_allow_list + cloudtrail_allow_list + rds_allow_list + dynamodb_allow_list + admin_list

                        if (s3_allow_list and not s3_deny_list) or (ec2_allow_list and not ec2_deny_list) or (iam_allow_list and not iam_deny_list) or (cloudtrail_allow_list and not cloudtrail_deny_list) or (rds_allow_list and not rds_deny_list) or (dynamodb_allow_list and not dynamodb_deny_list) or admin_list:
                            writer.writerow([role_name, ','.join(map(str,policies_list)), ','.join(map(str,set(s3_allow_list))), ','.join(map(str,set(s3_deny_list))), ','.join(map(str,set(ec2_allow_list))), ','.join(map(str,set(ec2_deny_list))),','.join(map(str,set(iam_allow_list))),','.join(map(str,set(iam_deny_list))),','.join(map(str,set(cloudtrail_allow_list))), ','.join(map(str,set(cloudtrail_deny_list))), ','.join(map(str,set(rds_allow_list))), ','.join(map(str,set(rds_deny_list))),','.join(map(str,set(dynamodb_allow_list))), ','.join(map(str,set(dynamodb_deny_list))),','.join(map(str,set(admin_list))), account_num,role_arn, AWSServiceroles, noncompliance])
                            print(role_name, f"{AWSServiceroles}noncompliance ---->", policies_list, s3_allow_list, s3_deny_list, ec2_allow_list, ec2_deny_list, admin_list, account_num)

                        else:
                            writer.writerow([role_name, ','.join(map(str,policies_list)), ','.join(map(str,set(s3_allow_list))), ','.join(map(str,set(s3_deny_list))), ','.join(map(str,set(ec2_allow_list))), ','.join(map(str,set(ec2_deny_list))),','.join(map(str,set(iam_allow_list))),','.join(map(str,set(iam_deny_list))),','.join(map(str,set(cloudtrail_allow_list))), ','.join(map(str,set(cloudtrail_deny_list))), ','.join(map(str,set(rds_allow_list))), ','.join(map(str,set(rds_deny_list))),','.join(map(str,set(dynamodb_allow_list))), ','.join(map(str,set(dynamodb_deny_list))),','.join(map(str,set(admin_list))), account_num,role_arn, AWSServiceroles,compliance])
                            print(role_name, f"{AWSServiceroles}compliance ---->", policies_list, s3_allow_list, s3_deny_list, ec2_allow_list, ec2_deny_list, admin_list, account_num)
                else:
                    if role_name in role_names:
                        print("Role is core/service",role_name)
                    else:
                        role_arn = role['Arn']
                        attached_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                        policies_list = []
                        s3_allow_list = []
                        s3_deny_list = []
                        ec2_allow_list = []
                        ec2_deny_list = []
                        iam_allow_list = []
                        iam_deny_list = []
                        cloudtrail_allow_list = []
                        cloudtrail_deny_list = []
                        rds_allow_list = []
                        rds_deny_list = []
                        dynamodb_allow_list = []
                        dynamodb_deny_list = []
                        admin_list = []
                        compliance = " Compliance Role"
                        noncompliance = "NonCompliance Role"

                        for policy in attached_policies:
                            #policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
                            policy_document = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                            #print(policy)
                            policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'],VersionId=policy_document)['PolicyVersion']['Document']
                            process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list)
                            policies_list.append(policy['PolicyName'])
                            if policy['PolicyName'] == 'AdministratorAccess':
                                admin_list.append("admin_access")

                        inline_policies = iam_client.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
                        for policy_name in inline_policies:
                            policy_version = iam_client.get_role_policy(RoleName=role['RoleName'], PolicyName=policy_name)['PolicyDocument']
                            process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list)
                            policies_list.append(policy_name)
                        total_allow = s3_allow_list + ec2_allow_list + iam_allow_list + cloudtrail_allow_list + rds_allow_list + dynamodb_allow_list + admin_list

                        if (s3_allow_list and not s3_deny_list) or (ec2_allow_list and not ec2_deny_list) or (iam_allow_list and not iam_deny_list) or (cloudtrail_allow_list and not cloudtrail_deny_list) or (rds_allow_list and not rds_deny_list) or (dynamodb_allow_list and not dynamodb_deny_list) or admin_list:
                            writer.writerow([role_name, ','.join(map(str,policies_list)), ','.join(map(str,set(s3_allow_list))), ','.join(map(str,set(s3_deny_list))), ','.join(map(str,set(ec2_allow_list))), ','.join(map(str,set(ec2_deny_list))),','.join(map(str,set(iam_allow_list))),','.join(map(str,set(iam_deny_list))),','.join(map(str,set(cloudtrail_allow_list))), ','.join(map(str,set(cloudtrail_deny_list))), ','.join(map(str,set(rds_allow_list))), ','.join(map(str,set(rds_deny_list))),','.join(map(str,set(dynamodb_allow_list))), ','.join(map(str,set(dynamodb_deny_list))),','.join(map(str,set(admin_list))), account_num,role_arn,Application, noncompliance])
                            print(role_name, f"{Application}noncompliance ---->", policies_list, s3_allow_list, s3_deny_list, ec2_allow_list, ec2_deny_list, admin_list, account_num)

                        else:
                            writer.writerow([role_name, ','.join(map(str,policies_list)), ','.join(map(str,set(s3_allow_list))), ','.join(map(str,set(s3_deny_list))), ','.join(map(str,set(ec2_allow_list))), ','.join(map(str,set(ec2_deny_list))),','.join(map(str,set(iam_allow_list))),','.join(map(str,set(iam_deny_list))),','.join(map(str,set(cloudtrail_allow_list))), ','.join(map(str,set(cloudtrail_deny_list))), ','.join(map(str,set(rds_allow_list))), ','.join(map(str,set(rds_deny_list))),','.join(map(str,set(dynamodb_allow_list))), ','.join(map(str,set(dynamodb_deny_list))),','.join(map(str,set(admin_list))), account_num,role_arn,Application, compliance])
                            print(role_name, f"{Application}compliance ---->", policies_list, s3_allow_list, s3_deny_list, ec2_allow_list, ec2_deny_list, admin_list, account_num)
    except Exception as e:
        print("Error:", e)

def process_policy_statement(policy_version, s3_perms_allow, s3_allow_list, s3_perms_deny, s3_deny_list, ec2_perms_allow, ec2_allow_list, ec2_perms_deny, ec2_deny_list,iam_perms_allow,iam_allow_list, iam_perms_deny, iam_deny_list, cloudtrail_perms_allow, cloudtrail_allow_list, cloudtrail_perms_deny, cloudtrail_deny_list, rds_perms_allow, rds_allow_list, rds_perms_deny, rds_deny_list, dynamodb_perms_allow, dynamodb_allow_list, dynamodb_perms_deny, dynamodb_deny_list, admin_access, admin_list):
    try:
      for idx, statement in enumerate(policy_version.get('Statement', []), start=1):
        effect = statement.get('Effect', 'N/A')
        actions = statement.get('Action', 'N/A')
        resources = statement.get('Resource', 'N/A')
        conditions = statement.get('Condition', 'N/A')
        #print(conditions)
        if resources.count("*") == 1 and conditions =='N/A':
            if effect == 'Allow':
                for s3_perm_allow in s3_perms_allow:
                    if s3_perm_allow in actions:
                        s3_allow_list.append(s3_perm_allow)
                for ec2_perm_allow in ec2_perms_allow:
                    if ec2_perm_allow in actions:
                        ec2_allow_list.append(ec2_perm_allow)
                for iam_perm_allow in iam_perms_allow:
                    if iam_perm_allow in actions:
                        iam_allow_list.append(iam_perm_allow)
                for cloudtrail_perm_allow in cloudtrail_perms_allow:
                    if cloudtrail_perm_allow in actions:
                        cloudtrail_allow_list.append(cloudtrail_perm_allow)
                for rds_perm_allow in rds_perms_allow:
                    if rds_perm_allow in actions:
                        rds_allow_list.append(rds_perm_allow)
                for dynamodb_perm_allow in dynamodb_perms_allow:
                    if dynamodb_perm_allow in actions:
                        dynamodb_allow_list.append(dynamodb_perm_allow)
                
            elif effect == 'Deny':
                for s3_perm_deny in s3_perms_deny:
                    if s3_perm_deny in actions:
                        s3_deny_list.append(s3_perm_deny)
                for ec2_perm_deny in ec2_perms_deny:
                    if ec2_perm_deny in actions:
                        ec2_deny_list.append(ec2_perm_deny)
                for iam_perm_deny in iam_perms_deny:
                    if iam_perm_deny in actions:
                        iam_deny_list.append(iam_perm_deny)
                for cloudtrail_perm_deny in cloudtrail_perms_deny:
                    if cloudtrail_perm_deny in actions:
                        cloudtrail_deny_list.append(cloudtrail_perm_deny)
                for rds_perm_deny in rds_perms_deny:
                    if rds_perm_deny in actions:
                        rds_deny_list.append(rds_perm_deny)
                for dynamodb_perm_deny in dynamodb_perms_deny:
                    if dynamodb_perm_deny in actions:
                        dynamodb_deny_list.append(dynamodb_perm_deny)
            
    except Exception as e1:
      print(e1)
      pass
if __name__ == "__main__":
    main()

import boto3
import json
import gzip
import time
import re

# AWS Configurations
S3_BUCKET_NAME = "aws-cloudtrail-logs-<account>-6a843a6e"
#OBJECT_KEY = "AWSLogs/<account>/CloudTrail/us-east-1/2025/03/14/CloudTrail_us-east-1_20250314T0140Z_8biw5uidZKa7aUUW.json.gz"
prefix = "AWSLogs/<account>/CloudTrail/us-east-1/"
DYNAMODB_TABLE_NAME = "IAMThreatLogs"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:<account>:SecurityAlerts"
CLAUDE_MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"

# AWS Clients
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
bedrock = boto3.client("bedrock-runtime")
sns = boto3.client("sns")

paginator = s3.get_paginator("list_objects_v2")
pages = paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix)
latest_log = max((obj for page in pages for obj in page.get("Contents", [])),key=lambda obj: obj["LastModified"],default=None)
if latest_log:
    print(latest_log["Key"]) 
else:
    print("No Log found")
Cloudtrail_Prefix = latest_log["Key"]
print(Cloudtrail_Prefix)

# IAM-related events to filter
IAM_EVENT_NAMES = [
    "CreateUser", "DeleteUser", "AttachRolePolicy", "DetachRolePolicy",
    "PassRole", "AssumeRole", "CreateAccessKey", "DeleteAccessKey",
    "UpdateRole", "UpdateUser", "PutUserPolicy", "DeleteUserPolicy",
    "PutRolePolicy", "DeleteRolePolicy"
]

def download_and_extract_logs():
    """Download CloudTrail logs from S3 and extract JSON."""
    try:
        print(f"Downloading {Cloudtrail_Prefix} from {S3_BUCKET_NAME}...")
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=Cloudtrail_Prefix)
        log_data = gzip.decompress(response["Body"].read()).decode("utf-8")
        return json.loads(log_data).get("Records", [])
    except Exception as e:
        print(f"Error downloading logs: {e}")
        return []

def filter_iam_logs(cloudtrail_events):
    """Filter CloudTrail logs for IAM-related events."""
    iam_logs = [log for log in cloudtrail_events if log.get("eventName", "") in IAM_EVENT_NAMES]
    print(f"Total IAM logs found: {len(iam_logs)}")
    return iam_logs

def analyze_with_claude(iam_logs):
    """Analyze IAM logs using AWS Bedrock Claude 3.5 Sonnet."""
    findings = []
    
    for log in iam_logs:
        prompt = f"\n\nHuman: Compare this IAM event with normal user behavior patterns. Identify any deviations that indicate suspicious activity. Score the risk on a scale of 1-10 and justify your decision and justification should be within 3 lines.:\n{json.dumps(log, indent=2)}\n\nAssistant:"
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 300
        }

        try:
            response = bedrock.invoke_model(
                modelId=CLAUDE_MODEL_ID,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(payload)
            )
            result = json.loads(response["body"].read().decode("utf-8"))
            risk_assessment = result.get("content", ["No analysis available"])[0]

            finding = {
                "event": log["eventName"],
                "user": log.get("userIdentity", {}).get("arn", "Unknown"),
                "risk_assessment": risk_assessment
            }
            #print(finding)
            findings.append(finding)
            #print(log["eventName"], str(log.get("userIdentity", {}).get("arn", "Unknown")), risk_assessment['text'])
            score = re.search(r'Score:\s*(\d+)/\d+',risk_assessment['text'])
            if score:
                risk_score = int(score.group(1))
                print(risk_score)
            else:
                print("Risk score not found")
            # If risk is high, send alert
            #if "analysis" in risk_assessment or "standard" in risk_assessment:
            #print(findings['content'])
            #print(finding)
            if risk_score >= 2:
                print("Sending an email")
                send_alert(finding)

        except Exception as e:
            print(f"Error invoking Claude 3.5: {e}")
            findings.append({
                "event": log["eventName"],
                "user": log.get("userIdentity", {}).get("arn", "Unknown"),
                "error": str(e)
            })

    return findings

def send_alert(finding):
    """Send security alerts via AWS SNS."""
    message = f"""
    === IAM Security Alert ===
    
    Event: {finding["event"]}
    User: {finding["user"]}
    Risk Assessment: {finding["risk_assessment"]['text']}
    
    Please investigate immediately!
    """
    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject="AWS IAM Security Alert"
        )
        print(f"Alert sent successfully! Message ID: {response['MessageId']}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

def save_to_dynamodb(analysis_results):
    """Store analysis results in DynamoDB."""
    table = dynamodb.Table(DYNAMODB_TABLE_NAME)

    for result in analysis_results:
        try:
            result["eventID"] = str(time.time())  # Generate unique event ID
            table.put_item(Item=result)
            #print(result)
        except Exception as e:
            print(f"Error saving to DynamoDB: {e}")

def main():
    """Main function to execute the analysis pipeline."""
    cloudtrail_events = download_and_extract_logs()
    
    if not cloudtrail_events:
        print("No CloudTrail logs found.")
        return
    
    iam_logs = filter_iam_logs(cloudtrail_events)
    
    if not iam_logs:
        print("No relevant IAM logs found.")
        return

    analysis_results = analyze_with_claude(iam_logs)
    save_to_dynamodb(analysis_results)

    print("\n==== IAM Threat Analysis Results ====")
    print(json.dumps(analysis_results, indent=2))
    #print(str(analysis_results['event']),str(analysis_results['risk_assessment']['text']))

if __name__ == "__main__":
    main()
