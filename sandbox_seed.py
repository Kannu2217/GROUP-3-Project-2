"""
Sandbox environment seeding + chaos drift injection.

AeroDrift is designed to run unmodified against a real AWS account
(swap the ``moto.mock_aws()`` context in ``daemon.py`` for real
credentials and nothing else changes). For development, grading and
CI, this module builds a small but realistic "secure baseline"
topology entirely inside `moto`'s in-memory AWS emulator:

    Internet
       |
    Internet Gateway
       |
    Public Route Table --- (0.0.0.0/0 -> IGW) ---> Public Subnet (DMZ)
                                                        |
                                                  sg-public-web (80/443 open)
                                                        |
                                                   web/bastion EC2

    Private Route Table (NO internet route) ---> Private Subnet (isolated-db)
                                                        |
                                             sg-private-db (5432 only from sg-public-web)
                                                        |
                                                  RDS Aurora Postgres (prod-aurora-cluster)

``inject_chaos_drift`` then reproduces the exact incident from the
project brief: an engineer (or a misfiring script) adds a
``0.0.0.0/0`` ingress rule straight onto the database security group,
instantly creating an Internet -> Database path that bypasses every
network boundary above.
"""

from __future__ import annotations

from dataclasses import dataclass

import boto3

from aerodrift.config import AWS_REGION, DATABASE_TAG_KEY, DATABASE_TAG_VALUE, INTERNET_CIDR


@dataclass
class SandboxResourceIds:
    vpc_id: str
    public_subnet_id: str
    private_subnet_id: str
    igw_id: str
    public_rt_id: str
    private_rt_id: str
    public_sg_id: str
    db_sg_id: str
    web_instance_id: str
    db_instance_id: str


def seed_sandbox_environment(region_name: str = AWS_REGION) -> SandboxResourceIds:
    """Build the secure baseline architecture inside the (mocked) AWS account."""
    ec2 = boto3.client("ec2", region_name=region_name)

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])

    public_subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{region_name}a"
    )["Subnet"]
    private_subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.20.0/24", AvailabilityZone=f"{region_name}b"
    )["Subnet"]

    ec2.create_tags(
        Resources=[public_subnet["SubnetId"]],
        Tags=[{"Key": "Name", "Value": "Subnet-Public-DMZ-1a"}],
    )
    ec2.create_tags(
        Resources=[private_subnet["SubnetId"]],
        Tags=[{"Key": "Name", "Value": "Subnet-Isolated-DB-1b"}],
    )

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    public_rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ec2.create_route(
        RouteTableId=public_rt_id, DestinationCidrBlock=INTERNET_CIDR, GatewayId=igw_id
    )
    ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet["SubnetId"])

    # Private route table deliberately has NO route to the internet gateway.
    private_rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ec2.associate_route_table(RouteTableId=private_rt_id, SubnetId=private_subnet["SubnetId"])

    public_sg = ec2.create_security_group(
        GroupName="sg-public-application-loadbalancer",
        Description="Public-facing web/bastion tier",
        VpcId=vpc_id,
    )
    public_sg_id = public_sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=public_sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": INTERNET_CIDR}]},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": INTERNET_CIDR}]},
        ],
    )

    db_sg = ec2.create_security_group(
        GroupName="sg-rds-aurora-isolated-db",
        Description="Private database tier — internet access forbidden",
        VpcId=vpc_id,
    )
    db_sg_id = db_sg["GroupId"]
    # Baseline-approved rule: Postgres only reachable from the public/app tier SG.
    ec2.authorize_security_group_ingress(
        GroupId=db_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "UserIdGroupPairs": [{"GroupId": public_sg_id}],
            }
        ],
    )

    web_instance = ec2.run_instances(
        ImageId="ami-0abcdef1234567890",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=public_subnet["SubnetId"],
        SecurityGroupIds=[public_sg_id],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "bastion-app-web-01"}]}
        ],
    )["Instances"][0]

    db_instance = ec2.run_instances(
        ImageId="ami-0abcdef1234567890",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.medium",
        SubnetId=private_subnet["SubnetId"],
        SecurityGroupIds=[db_sg_id],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "prod-aurora-postgres-01"},
                    {"Key": DATABASE_TAG_KEY, "Value": DATABASE_TAG_VALUE},
                ],
            }
        ],
    )["Instances"][0]

    return SandboxResourceIds(
        vpc_id=vpc_id,
        public_subnet_id=public_subnet["SubnetId"],
        private_subnet_id=private_subnet["SubnetId"],
        igw_id=igw_id,
        public_rt_id=public_rt_id,
        private_rt_id=private_rt_id,
        public_sg_id=public_sg_id,
        db_sg_id=db_sg_id,
        web_instance_id=web_instance["InstanceId"],
        db_instance_id=db_instance["InstanceId"],
    )


def inject_chaos_drift(db_sg_id: str, region_name: str = AWS_REGION, port: int = 5432) -> dict:
    """
    Simulate the exact incident described in the project brief: someone
    accidentally opens the production database security group to the
    entire internet.

    Returns the ingress permission dict that was added, so the caller
    (or the drift detector) has the ground truth for what changed.
    """
    ec2 = boto3.client("ec2", region_name=region_name)
    permission = {
        "IpProtocol": "tcp",
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": INTERNET_CIDR, "Description": "TEMP - engineer debugging, revert me"}],
    }
    ec2.authorize_security_group_ingress(GroupId=db_sg_id, IpPermissions=[permission])
    return permission
