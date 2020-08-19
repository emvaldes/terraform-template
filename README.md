# HashiCorp - Terraform AWS Cloud Deployment (pre-release)
## HashiCorp Terraform - Infrastructure Management

![GitHub Actions - Terraform](https://github.com/emvaldes/terraform-awscloud/workflows/GitHub%20Actions%20-%20Terraform/badge.svg)

It's imperative that these GitHub Secrets are set:

```bash
AWS_ACCESS_KEYPAIR:     Terraform AWS KeyPair (PEM file).
AWS_ACCESS_KEY_ID:      Terraform AWS Access Key-Id (e.g.: AKIA2...VT7DU).
AWS_DEFAULT_ACCOUNT:    The AWS Account number (e.g.: 123456789012).
AWS_DEFAULT_PROFILE:    The AWS Credentials Default User (e.g.: default).
AWS_DEFAULT_REGION:     The AWS Default Region (e.g.: us-east-1)
AWS_DEPLOY_TERRAFORM:   Enable|Disable (true|false) deploying terraform infrastructure
AWS_DESTROY_TERRAFORM:  Enable|Disable (true|false) destroying terraform infrastructure
AWS_SECRET_ACCESS_KEY:  Terraform AWS Secret Access Key (e.g.: zBqDUNyQ0G...IbVyamSCpe)
DEVOPS_ACCESS_POLICY:   Defines the STS TrustPolicy for the Terraform user.
DEVOPS_ACCESS_ROLE:     Defines the STS Assume-Role for the Terraform user.
INSPECT_DEPLOYMENT:     Control-Process to enable auditing infrastructure state.
UPDATE_PYTHON_LATEST:   Enforce the upgrade from the default 2.7 to symlink to the 3.6
UPDATE_SYSTEM_LATEST:   Enforce the upgrade of the Operating System.
```

### The following features described here are not really scalable and will need to be reviewed.

The **AWS_ACCESS_KEYPAIR** is a GitHub Secret used to auto-populate the ***~/access-keypair*** file for post-deployment configurations.

In the event of needing to target a different account, change it in the GitHub Secrets **AWS_DEFAULT_ACCOUNT**. Keep in mind that both **AWS_SECRET_ACCESS_KEY** and **AWS_ACCESS_KEY_ID** are account specific.<br>

There is no need to midify the GitHub Secret **AWS_DEFAULT_PROFILE** as there is only one section defined in the ~/.aws/credentials file. If a specific AWS Region is required, then update the **AWS_DEFAULT_REGION** but keep in mind that any concurrent build will be pre-set.

The logical switch **AWS_DEPLOY_TERRAFORM** is set to enable or disable the deployment of the terraform plan is a safety messure to ensure that a control-mechanism is in place. The same concept applies to **AWS_DESTROY_TERRAFORM** which is set to enable or disable the destruction of the previously deployed terraform infrastructure.

**Note**: In addition to these basic/core requirements, it's important that a key-name **terraform** be created/active in AWS as it's hardcoded in this prototype. I will find a more efficient solution to this.

```shell
DEFAULT_PROFILE='default';
DEFAULT_REGION='us-east-1';

AWS_DEFAULT_ACCOUNT='123456789012';

DEVOPS_GROUP='devops';
DEVOPS_USER='terraform';

DEVOPS_ACCESS_POLICY='DevOps--Custom-Access.Policy';
DEVOPS_ACCESS_ROLE='DevOps--Custom-Access.Role';
DEVOPS_CUSTOM_BOUNDARY='Devops--Permission-Boundaries.Policy';
DEVOPS_ASSUME_POLICY='DevOps--Assume-Role.Policy';

declare -a AWS_CREDENTIALS_TOKENS=(
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN
    AWS_TOKEN_EXPIRES
    AWS_PRINCIPAL_ARN
  );
export DEFAULT_ROLEDURATION=3600;
```

```console
CONFIG_JSON="/tmp/${DEVOPS_ACCESS_POLICY}.json";
tee -a ${CONFIG_JSON} <<BLOCK
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "StmtEC2",
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtELB",
            "Effect": "Allow",
            "Action": "elasticloadbalancing:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtIAM",
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtS3",
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}

BLOCK
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-policy \
    --policy-name ${DEVOPS_ACCESS_POLICY} \
    --policy-document file:///${CONFIG_JSON} ;
```

```json
{
    "Policy": {
        "PolicyName": "{{ DEVOPS_ACCESS_POLICY }}",
        "PolicyId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:policy/{{ DEVOPS_ACCESS_POLICY }}",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2020-08-17T06:15:48+00:00",
        "UpdateDate": "2020-08-17T06:15:48+00:00"
    }
}
```

```console
CONFIG_JSON="/tmp/${DEVOPS_CUSTOM_BOUNDARY}.json";
tee -a ${CONFIG_JSON} <<BLOCK
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:*",
                "organizations:DescribeAccount",
                "organizations:DescribeOrganization",
                "organizations:DescribeOrganizationalUnit",
                "organizations:DescribePolicy",
                "organizations:ListChildren",
                "organizations:ListParents",
                "organizations:ListPoliciesForTarget",
                "organizations:ListRoots",
                "organizations:ListPolicies",
                "organizations:ListTargetsForPolicy"
            ],
            "Resource": "*"
        },
        {
            "Action": "ec2:*",
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "elasticloadbalancing:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "cloudwatch:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "autoscaling:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": [
                        "autoscaling.amazonaws.com",
                        "ec2scheduled.amazonaws.com",
                        "elasticloadbalancing.amazonaws.com",
                        "spot.amazonaws.com",
                        "spotfleet.amazonaws.com",
                        "transitgateway.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}

BLOCK
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-policy \
    --policy-name ${DEVOPS_CUSTOM_BOUNDARY} \
    --policy-document file:///${CONFIG_JSON} ;
```

```json
{
    "Policy": {
        "PolicyName": "{{ DEVOPS_CUSTOM_BOUNDARY }}",
        "PolicyId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:policy/{{ DEVOPS_CUSTOM_BOUNDARY }}",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2020-08-17T06:16:37+00:00",
        "UpdateDate": "2020-08-17T06:16:37+00:00"
    }
}
```


```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-group \
    --group-name ${DEVOPS_GROUP} ;
```

```json
{
    "Group": {
        "Path": "/",
        "GroupName": "devops",
        "GroupId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:group/devops",
        "CreateDate": "2020-08-17T06:25:51+00:00"
    }
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-user \
    --user-name ${DEVOPS_USER} ;
```

```json
{
    "User": {
        "Path": "/",
        "UserName": "terraform",
        "UserId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}",
        "CreateDate": "2020-08-17T06:26:16+00:00"
    }
}
```

```shell
declare -a session_items=(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY);
declare -a iamuser_accesskeys=($(
    aws --profile ${DEFAULT_PROFILE} \
        --region ${DEFAULT_REGION} \
        iam create-access-key \
        --user-name ${DEVOPS_USER} \
        --query 'AccessKey.{aki:AccessKeyId,sak:SecretAccessKey}' \
        --output text
  ));
counter=0; for xkey in "${iamuser_accesskeys[@]}"; do
  echo -e "AWS Crendential :: ${session_items[${counter}]} = ${xkey}";
  eval "export ${session_items[${counter}]}=${xkey}";
  ((counter++));
done;
```

```shell
mkdir -p ${HOME}/.aws/access/${AWS_DEFAULT_ACCOUNT}/;
target_credfile="${HOME}/.aws/access/${AWS_DEFAULT_ACCOUNT}/${DEFAULT_PROFILE}.credentials";
echo -e "[${DEFAULT_PROFILE}]
aws_access_key_id = ${AWS_ACCESS_KEY_ID}
aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}
aws_session_token =
x_principal_arn = arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${DEVOPS_USER}
x_security_token_expires =
" > ${target_credfile};
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam add-user-to-group \
    --user-name ${DEVOPS_USER} \
    --group-name ${DEVOPS_GROUP} ;
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam get-group \
    --group-name ${DEVOPS_GROUP} ;
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "terraform",
            "UserId": "***",
            "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}",
            "CreateDate": "2020-08-17T06:26:16+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "devops",
        "GroupId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:group/devops",
        "CreateDate": "2020-08-17T06:25:51+00:00"
    }
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-role \
    --path / \
    --role-name ${DEVOPS_ACCESS_ROLE} \
    --max-session-duration 3600 \
    --description "DevOps Infrastructure Deployment - Automation Services." \
    --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${DEVOPS_USER}\"]},\"Action\":[\"sts:AssumeRole\"]}]}"
```

```json
{
    "Role": {
        "Path": "/",
        "RoleName": "{{ DEVOPS_ACCESS_ROLE }}",
        "RoleId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:role/{{ DEVOPS_ACCESS_ROLE }}",
        "CreateDate": "2020-08-17T06:27:09+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}"
                        ]
                    },
                    "Action": [
                        "sts:AssumeRole"
                    ]
                }
            ]
        }
    }
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam attach-role-policy \
    --role-name ${DEVOPS_ACCESS_ROLE} \
    --policy-arn arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:policy/${DEVOPS_ACCESS_POLICY} ;
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam get-role \
    --role-name ${DEVOPS_ACCESS_ROLE} ;
```

```json
{
    "Role": {
        "Path": "/",
        "RoleName": "{{ DEVOPS_ACCESS_ROLE }}",
        "RoleId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:role/{{ DEVOPS_ACCESS_ROLE }}",
        "CreateDate": "2020-08-17T06:27:09+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "DevOps Infrastructure Deployment - Automation Services.",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {}
    }
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam list-attached-role-policies \
    --role-name ${DEVOPS_ACCESS_ROLE};
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "{{ DEVOPS_ACCESS_POLICY }}",
            "PolicyArn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:policy/{{ DEVOPS_ACCESS_POLICY }}"
        }
    ]
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam put-role-permissions-boundary \
    --permissions-boundary arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:policy/${DEVOPS_CUSTOM_BOUNDARY} \
    --role-name ${DEVOPS_ACCESS_ROLE};
```


```shell
CONFIG_JSON="/tmp/${DEVOPS_ASSUME_POLICY}.json";
tee -a ${CONFIG_JSON} <<BLOCK
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:role/${DEVOPS_ACCESS_ROLE}"
    }
}

BLOCK
```

```json
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:role/{{ DEVOPS_ACCESS_ROLE }}"
    }
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-policy \
    --policy-name ${DEVOPS_ASSUME_POLICY} \
    --policy-document file:///${CONFIG_JSON} ;
```

```json
{
    "Policy": {
        "PolicyName": "{{ DEVOPS_ASSUME_POLICY }}",
        "PolicyId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:policy/{{ DEVOPS_ACCESS_ROLE }}",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2020-08-17T06:42:13+00:00",
        "UpdateDate": "2020-08-17T06:42:13+00:00"
    }
}
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam attach-group-policy \
    --policy-arn arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:policy/${DEVOPS_ASSUME_POLICY} \
    --group-name ${DEVOPS_GROUP};
```

```shell
aws --profile ${DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam list-attached-group-policies \
    --group-name ${DEVOPS_GROUP};
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "{{ DEVOPS_ASSUME_POLICY }}",
            "PolicyArn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:policy/{{ DEVOPS_ASSUME_POLICY }}"
        }
    ]
}
```

```shell
AWS_SHARED_CREDENTIALS_FILE="${target_credfile}";
```

```shell
declare -a session_token=($(
    aws --profile ${section} \
        --region ${DEFAULT_REGION} \
        sts assume-role \
        --role-arn arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:role/${DEVOPS_ACCESS_ROLE} \
        --role-session-name "${session}-$(date +"%Y%m%d%H%M%S")" \
        --duration-seconds ${DEFAULT_ROLEDURATION} \
        --query 'Credentials.{aki:AccessKeyId,sak:SecretAccessKey,stk:SessionToken,sts:Expiration}' \
        --output text
  ));
local counter=0; for xkey in "${session_token[@]}"; do
  eval "export ${AWS_CREDENTIALS_TOKENS[$((counter++))]}=${xkey}";
done;
```

```shell
aws --profile ${DEVOPS_USER} \
    --region ${DEFAULT_REGION} \
    sts get-caller-identity ;
```

```json
{
    "UserId": "***",
    "Account": "{{ AWS_DEFAULT_ACCOUNT }}",
    "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}"
}
```

```shell
declare -a credentials=(
    aws_access_key_id~${AWS_ACCESS_KEY_ID}
    aws_secret_access_key~${AWS_SECRET_ACCESS_KEY}
    aws_session_token~${AWS_SESSION_TOKEN}
    x_security_token_expires~${AWS_TOKEN_EXPIRES}
    x_principal_arn~arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${profile}
  );
for credential in ${credentials[@]}; do
  sed -i '' -e "s|^\(${credential%\~*}\)\( =\)\(.*\)$|\1\2 ${credential#*\~}|g" ${AWS_SHARED_CREDENTIALS_FILE} ;
done;
cat ${AWS_SHARED_CREDENTIALS_FILE} ;
```

```shell
aws --profile ${DEVOPS_USER} \
    --region ${DEFAULT_REGION} \
    sts get-caller-identity ;
```

```json
{
    "UserId": "***:terraform",
    "Account": "{{ AWS_DEFAULT_ACCOUNT }}",
    "Arn": "arn:aws:sts::{{ AWS_DEFAULT_ACCOUNT }}:assumed-role/{{ DEVOPS_ACCESS_ROLE }}/{{ DEVOPS_USER }}"
}
```

---

# Demonstration:

```shell
amazon-assumerole terraform terraform TerraformPipeline verbose ;
-rw-r--r--  1 emvaldes  staff  235 Aug 18 17:46 /Users/emvaldes/.aws/access/{{ AWS_DEFAULT_ACCOUNT }}/terraform.credentials
```

```shell
[terraform]
aws_access_key_id = ***
aws_secret_access_key = ***
aws_session_token = IQoJb3JpZ2...OA5ZfYCw==
x_principal_arn = arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}
x_security_token_expires = 2020-08-19T01:46:48+00:00
```

```json
{
    "UserId": "***:TerraformPipeline-20200818174647",
    "Account": "{{ AWS_DEFAULT_ACCOUNT }}",
    "Arn": "arn:aws:sts::{{ AWS_DEFAULT_ACCOUNT }}:assumed-role/{{ DEVOPS_ACCESS_ROLE }}/TerraformPipeline-20200818174647"
}
```

```shell
aws --profile ${DEVOPS_USER} \
    --region ${DEFAULT_REGION} \
    iam list-users ;
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "terraform",
            "UserId": "***",
            "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}",
            "CreateDate": "2020-08-17T06:26:16+00:00"
        }
    ]
}
```

```shell
assumedrole-timeframe terraform verbose ;

Token Expires: 2020-08-19 01:46:48 [1597801608]
 Current Date: 2020-08-19 00:47:03 [1597798023]

The Assumed-Role Session has 59 minutes remaining until it expires.
```

---

Please, make sure your **AWS IAM Policy** allows for something like this and enforce the appropriate ***User Permissions Boundary***:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::terraform-states-{{ AWS_DEFAULT_ACCOUNT }}",
                "arn:aws:s3:::terraform-states-{{ AWS_DEFAULT_ACCOUNT }}/*"
            ]
        }
    ]
}
```

I would also recommend that you append an ***AWS IAM Inline Policy*** to your **terraform** ***AWS IAM User account***:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "StmtCustomIAmPolicy",
            "Effect": "Deny",
            "Action": [
                "iam:AttachRolePolicy",
                "iam:UpdateAccessKey",
                "iam:DetachUserPolicy",
                "iam:CreateLoginProfile",
                "ec2:RequestSpotInstances",
                "organizations:InviteAccountToOrganization",
                "iam:AttachUserPolicy",
                "lightsail:Update*",
                "iam:ChangePassword",
                "iam:DeleteUserPolicy",
                "iam:PutUserPolicy",
                "lightsail:Create*",
                "lambda:CreateFunction",
                "lightsail:DownloadDefaultKeyPair",
                "iam:UpdateUser",
                "organizations:CreateAccount",
                "iam:UpdateAccountPasswordPolicy",
                "iam:CreateUser",
                "lightsail:Delete*",
                "iam:AttachGroupPolicy",
                "ec2:StartInstances",
                "iam:PutUserPermissionsBoundary",
                "iam:PutGroupPolicy",
                "lightsail:Start*",
                "lightsail:GetInstanceAccessDetails",
                "iam:CreateAccessKey",
                "organizations:CreateOrganization"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

I would also setup the target ***AWS S3 Bucket Policy*** based on these standard configurations:

```json
{
    "Version": "2012-10-17",
    "Id": "PolicyTerraformS3Bucket",
    "Statement": [
        {
            "Sid": "StmtTerraformS3Bucket",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_USER }}"
            },
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::terraform-states-{{ AWS_DEFAULT_ACCOUNT }}/*"
        }
    ]
}
```

Block ALL Bucket public access (bucket settings: ON)
<ol>
<li>Block public access to buckets and objects granted through new access control lists (ACLs)</li>
<li>Block public access to buckets and objects granted through any access control lists (ACLs)</li>
<li>Block public access to buckets and objects granted through new public bucket or access point policies</li>
<li>Block public and cross-account access to buckets and objects through any public bucket or access point policies</li>
</ol>

**Reference**: This project is based on the original training materials from [PluralSight](https://www.pluralsight.com).<br />
[Terraform - Getting Started](https://app.pluralsight.com/library/courses/getting-started-terraform) by [Ned Bellavance](https://app.pluralsight.com/profile/author/edward-bellavance)
