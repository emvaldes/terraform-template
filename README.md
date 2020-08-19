# HashiCorp - Terraform AWS Cloud Deployment
## HashiCorp Terraform - Infrastructure Management

![GitHub Actions - Terraform Controller](https://github.com/emvaldes/terraform-awscloud/workflows/GitHub%20Actions%20-%20Terraform%20Controller/badge.svg)

Scripting everything is not always a good thing if you do not have an understanding of what is getting scripted. This can be very detrimental factor in understanding and troubleshooting how things works. It masks the behavior and logic for the sake of efficiency.

I have always focused in supporting one key factor in automation:
### [Readability](https://en.wikipedia.org/wiki/Computer_programming#Readability_of_source_code)


Combining all these steps into a single script is super simple but for me is more important to explain how it works than to obscure its logic with something scripted that then you will not be able to understand.

I will guide you now through the process of configuring AWS Assume Role from scratch without having to use the Web-Console. The process goes as follow:

### These are the steps you need to follow in order to import this project into your workflow:

---

**<span style="color:red">A</span>** -) Fork this repo into your own environment as you will need to execute your own GitHub Pipeline. e.g.: [Deploy-Terraform](https://github.com/emvaldes/terraform-awscloud/blob/master/.github/workflows/deploy-terraform.yaml) using your GitHub Secrets.

---

**<span style="color:red">B</span>** -) It's imperative that as soon as you fork this GitHub Repo into your own account/organization, these GitHub Secrets are set:

```console
AWS_ACCESS_KEY_ID           Service-Account AWS Access Key-Id (e.g.: AKIA2...VT7DU).
AWS_DEFAULT_ACCOUNT         The AWS Account number (e.g.: 123456789012).
AWS_DEFAULT_PROFILE         The AWS Credentials Default User (e.g.: default).
AWS_DEFAULT_REGION          The AWS Default Region (e.g.: us-east-1)
AWS_SECRET_ACCESS_KEY       Service-Account AWS Secret Access Key (e.g.: zBqDUNyQ0G...IbVyamSCpe)
BACKUP_TERRAFORM            Enable|Disable (true|false) backing-up terraform plan/state
DEPLOY_TERRAFORM            Enable|Disable (true|false) deploying terraform infrastructure
DESTROY_TERRAFORM           Enable|Disable (true|false) destroying terraform infrastructure
DEVOPS_ACCESS_POLICY        Defines the AWS IAM Policy: DevOps--Custom-Access.Policy
DEVOPS_ACCESS_ROLE          Defines the AWS IAM Role: DevOps--Custom-Access.Role
DEVOPS_ACCOUNT_NAME         A placeholder for the Deployment Service Account name (devops).
DEVOPS_ASSUMEROLE_POLICY    Defines the AWS IAM Policy: DevOps--Assume-Role.Policy
DEVOPS_BOUNDARIES_POLICY    Defines the AWS IAM Policy: Devops--Permission-Boundaries.Policy
DYNAMODB_DEFAULT_REGION     Single-Region tables are used (e.g.: us-east-1)
INSPECT_DEPLOYMENT          Enable|Disable (true|false) inspecting deployment
PRIVATE_KEYPAIR_FILE        Terraform AWS KeyPair (location: ~/.ssh/id_rsa).
PRIVATE_KEYPAIR_NAME        Terraform AWS KeyPair (e.g.: devops).
PRIVATE_KEYPAIR_SECRET      Terraform AWS KeyPair (PEM, Private file)
PROVISION_TERRAFORM         Enable|Disable (true|false) the provisioning of the terraform-toolset
S3BUCKET_CONTAINER          Identifies where the deployment will be stored
TARGET_WORKSPACE            Identifies which is your default (current) environment
UPDATE_PYTHON_LATEST        Enable|Disable (true|false) updating Python version
UPDATE_SYSTEM_LATEST        Enable|Disable (true|false) updating operating system
```

### The following features described here are not really scalable and will need to be refactored at some point.
**Note**: The temporary solution I have considered and enabled is the use of workflow-dispatch but it's a manual step and this must be implemented differently.

The **AWS_ACCESS_KEYPAIR** is a GitHub Secret used to auto-populate the ***~/access-keypair*** file for post-deployment configurations.<br>
**Note**: There is the use-case of requiring different AWS Access KeyPairs for each environment so there is segregation in access.

In the event of needing to target a different AWS Account, change it in the GitHub Secrets **AWS_DEFAULT_ACCOUNT**. Keep in mind that both **AWS_SECRET_ACCESS_KEY** and **AWS_ACCESS_KEY_ID** are account specific.<br>

There is no need to midify the GitHub Secret **AWS_DEFAULT_PROFILE** as there is only one section defined in the ***~/.aws/credentials*** file. If a specific AWS Region is required, then update the **AWS_DEFAULT_REGION** but keep in mind that any concurrent build will be pre-set.

The logical switch **AWS_DEPLOY_TERRAFORM** is set to enable or disable the deployment of the terraform plan is a safety messure to ensure that a control-mechanism is in place. The same concept applies to **AWS_DESTROY_TERRAFORM** which is set to enable or disable the destruction of the previously deployed terraform infrastructure.

The DevOps Access Policy/Role (**DEVOPS_ACCESS_POLICY** and **DEVOPS_ACCESS_ROLE**) I have implemented and documented in here (keep reading).

The DevOps Service Account (**DEVOPS_ACCOUNT_NAME**) is a placeholder abstraction for the name of the user associated with Terraform deployments (e.g.: terraform). You could have other naming conventions in your environment that I cannot predict for everyone nor try to enforce.

The DevOps User IAM ID (**DEVOPS_ACCOUNT_ID**) is not like any of these GitHub Secrets scalable as if you target a deployment in another account it will be different and then it becomes impossible to mask it during the deployment-output.

The Inspect Deployment (**INSPECT_DEPLOYMENT**) is intended as a boolean value to define if at some point in the execution of this GitHub Pipeline there is need for evaluating resources in the deployed infrastructure.

The Update Python/System Latest (**UPDATE_PYTHON_LATEST** and **UPDATE_SYSTEM_LATEST**) is designed to confirm if upgrading Python and the GitHub Runner's Operating System during deployment.

---

**<span style="color:red">C</span>** -) In order for the Deploy-Terraform GitHub Action to become active in your forked repo, you could modify (my recommendation) the [Terraform Workspace](https://github.com/takeda-netsrv-eduardovaldes/terraform-awscloud/blob/master/workspace) file so that the GitHub Pipeline YAML file can be activated in your GitHub Actions.

---

I have documented here the steps that you could perform in your environment if you do not have a proper setup for [AWS STS Assume Role capabilities](https://docs.aws.amazon.com/cli/latest/reference/sts/#:~:text=The%20AWS%20Security%20Token%20Service,you%20authenticate%20(federated%20users)).

You must define these environment variables that will be used across these steps.
**Note**: Make sure to set the **${AWS_DEFAULT_ACCOUNT}** with the correct information (the AWS Account you will be deploying this setup).

Also, keep in mind that I have a preference for this specific set of DevOps* Policies/Roles naming conventions but you have the freedom to define them as you see fit in your own environment. Just make sure that those are properly populated in the GitHub Secrets placeholders I have constructed for them.

---

**<span style="color:red">00</span>** -) Export all required environment variables.

```shell
export AWS_MASTER_USER='eduardo.valdes';
export AWS_COMPANY_NAME='anonymous';

export AWS_PUBLIC_SSHKEY="${HOME}/.ssh/public/${AWS_COMPANY_NAME}.pub";
export AWS_PRIVATE_SSHKEY="${HOME}/.ssh/private/${AWS_COMPANY_NAME}";

export AWS_DEFAULT_PROFILE="${AWS_COMPANY_NAME}-${AWS_MASTER_USER}";

export DEFAULT_REGION='us-east-1';
export AWS_DEFAULT_ACCOUNT='123456789012';
export AWS_EMAIL_ADDRESS='***@***';

export AWS_ACCESS_KEY_ID='***'
export AWS_SECRET_ACCESS_KEY='***'
export AWS_PRINCIPAL_ARN="arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${AWS_MASTER_USER}";

export DEVOPS_ACCOUNT_GROUP='devops';
export DEVOPS_ACCOUNT_NAME='terraform';

export AWS_S3BUCKET_NAME="${DEVOPS_ACCOUNT_NAME}-states-${AWS_DEFAULT_ACCOUNT}";
export AWS_TARGET_PROFILE="${AWS_COMPANY_NAME}-${DEVOPS_ACCOUNT_NAME}";

export AWS_ACCESS_KEYPAIR="${HOME}/.ssh/private/${AWS_TARGET_PROFILE}";

export DEVOPS_ACCESS_POLICY='DevOps--Custom-Access.Policy';
export DEVOPS_ACCESS_ROLE='DevOps--Custom-Access.Role';

export DEVOPS_CUSTOM_BOUNDARY='Devops--Permission-Boundaries.Policy';
export DEVOPS_ASSUME_POLICY='DevOps--Assume-Role.Policy';

export DEVOPS_GITHUB_USER='emvaldes';
export DEVOPS_GITHUB_REPO='terraform-awscloud';

declare -a AWS_CREDENTIALS_TOKENS=(
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN
    AWS_TOKEN_EXPIRES
    AWS_PRINCIPAL_ARN
  );
export DEFAULT_ROLEDURATION=3600;
```

---

[Endpoints available for GitHub Apps](https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps)

<a href="https://docs.github.com/en/rest/reference/actions#list-repository-secrets">List repository secrets</a><br>
<a href="https://docs.github.com/en/rest/reference/actions#get-a-repository-public-key">Get a repository public key</a><br>
<a href="https://docs.github.com/en/rest/reference/actions#get-a-repository-secret">Get a repository secret</a><br>
<a href="https://docs.github.com/en/rest/reference/actions#create-or-update-a-repository-secret">Create or update a repository secret</a><br>
<a href="https://docs.github.com/en/rest/reference/actions#delete-a-repository-secret">Delete a repository secret</a>

First of all, go and create a [GitHub Personal Token](https://github.com/settings/tokens):<br>
https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token <br>

**<span style="color:red">01</span>** -) Then create two environment variables to enable the interaction with the GitHub REST API to manage secrets:

```shell
export github_personal_token="***";
export github_restapi_application="application/vnd.github.v3+json";
```

**<span style="color:red">02</span>** -) Exporting ***${github_public_key}***, ***${github_public_key_id}***

```shell
eval $(
    curl --silent \
         --header "Authorization: token ${github_personal_token}" \
         --header "Accept: ${github_restapi_application}" \
         https://api.github.com/repos/${DEVOPS_GITHUB_USER}/${DEVOPS_GITHUB_REPO}/actions/secrets/public-key \
    | jq -r "to_entries|map(\"export github_public_\(.key)=\(.value|tostring)\")|.[]") ;
```

```json
{"key_id":"?","key": "?"}
```

### <a name="encrypt-secret"></a>Encrypt your secret using [pynacl](https://pynacl.readthedocs.io/en/stable/public/#nacl-public-sealedbox) with Python 3.

```shell
python -m pip install pynacl ;

Collecting pynacl
  Downloading PyNaCl-1.4.0-cp35-abi3-macosx_10_10_x86_64.whl (380 kB)
     |████████████████████████████████| 380 kB 1.1 MB/s
Requirement already satisfied: six in /Users/emvaldes/Library/Python/3.8/lib/python/site-packages (from pynacl) (1.14.0)
Requirement already satisfied: cffi>=1.4.1 in /Users/emvaldes/Library/Python/3.8/lib/python/site-packages (from pynacl) (1.13.2)
Requirement already satisfied: pycparser in /Users/emvaldes/Library/Python/3.8/lib/python/site-packages (from cffi>=1.4.1->pynacl) (2.19)
Installing collected packages: pynacl
Successfully installed pynacl-1.4.0

WARNING: You are using pip version 20.0.2; however, version 20.2.2 is available.
You should consider upgrading via the '/Library/Frameworks/Python.framework/Versions/3.8/bin/python -m pip install --upgrade pip' command.
python -m pip install --upgrade pip ;
Collecting pip
  Downloading pip-20.2.2-py2.py3-none-any.whl (1.5 MB)
     |████████████████████████████████| 1.5 MB 1.2 MB/s
Installing collected packages: pip
  Attempting uninstall: pip
    Found existing installation: pip 20.0.2
    Uninstalling pip-20.0.2:
      Successfully uninstalled pip-20.0.2
Successfully installed pip-20.2.2
```

[github-secrets.py](https://github.com/emvaldes/terraform-awscloud/blob/edf9d309c3b749b5a20da13ece30bad57ee693b7/scripts/github-secrets.py#L8)

**Note**: This Python function is the only portion of this automation that does not work. So the encrypted content is properly submitted but it's not accepted. As a result to that, the secrets are empty.

```python
#!/usr/bin/env python

import sys, argparse, json

from base64 import b64encode
from nacl import encoding, public

def encrypt( encrypt_key: str, secret_value: str ) -> str:
    ## private_key = public.PrivateKey.generate()
    public_key = public.PublicKey( encrypt_key.encode( "utf-8" ), encoding.Base64Encoder() )
    sealed_box = public.SealedBox( public_key )
    encrypted = sealed_box.encrypt( secret_value.encode( "utf-8" ) )
    ### print(encrypted)
    return b64encode( encrypted ).decode( "utf-8" )

def main():
    ## print ( 'Total Arguments?:', format( len( sys.argv ) ) )
    ## print ( '   Argument List:', str( sys.argv ) )
    parser = argparse.ArgumentParser()
    parser.add_argument( '--public-key', dest='public_key',  type=str, help='Encryption Public-Key' )
    parser.add_argument( '--content', dest='content',  type=str, help='Source Content' )
    options = parser.parse_args()
    print( encrypt( options.public_key, options.content ) )

if __name__ == '__main__':
    main()
```

**<span style="color:red">03</span>** -) Define a function for creating the GitHub Secrets:

[create-github-secret](https://github.com/emvaldes/devops-tools/blob/aaff2d5b159285862c6b197f66c4a637d912e538/functions/devops-tools.functions#L44)

```shell
## Requires Environment variables:
## github-repo, github-token, github-user, secret-name, secret-value
function create_github_secret () {
    ## tracking_process ${FUNCNAME} "${@}";
    oIFS="${IFS}";
    for xitem in "${@}"; do
      IFS='='; set `echo -e "${xitem}" | sed -e '1s|^\(-\)\{1,\}||'`
      [[ ${1#*\--} = "github-repo" ]] && export github_repo="${2}";
      [[ ${1#*\--} = "github-token" ]] && export github_token="${2}";
      [[ ${1#*\--} = "github-user" ]] && export github_user="${2}";
      [[ ${1#*\--} = "secret-name" ]] && export secret_name="${2}";
      [[ ${1#*\--} = "secret-value" ]] && export secret_value="${2}";
      [[ ${1#*\--} = "interactive" ]] && export interactive_mode='true';
      ## [[ ${1#*\--} = "dry-run" ]] && export dry_run="${2}";
      [[ ${1#*\--} = "verbose" ]] && export verbose='true';
      [[ ${1#*\--} = "help" ]] && export display_help='true';
    done; IFS="${oIFS}";
    export github_restapi="application/vnd.github.v3+json";
    eval $(
        curl --silent \
             --header "Authorization: token ${github_token}" \
             --header "Accept: ${github_restapi}" \
             https://api.github.com/repos/${github_user}/${github_repo}/actions/secrets/public-key \
        | jq -r "to_entries|map(\"export github_public_\(.key)=\(.value|tostring)\")|.[]") ;
    if [[ ${#github_public_key} -gt 0 ]]; then
            [[ ${verbose} == true ]] && echo -e "\nGitHub Public-Key:   ${github_public_key}";
      else  echo -e "\nWarning: Unable to fetch GitHub Public Encryption-Key! \n";
            return 1;
    fi;
    encrypted=$(
        github-secrets.py --public-key ${github_public_key} \
                          --content "${secret_value}"
      );
    if [[ ${verbose} == true ]]; then
      echo -e;
      echo -e "DevOps GitHub User:  ${github_user}";
      echo -e "DevOps GitHub Repo:  ${github_repo}";
      echo -e "GitHub Repos Token:  ${github_token}";
      echo -e "GitHub RESTAPI App:  ${github_restapi}";
      echo -e "GitHub Public Key:   ${github_public_key}";
      echo -e "GitHub Secret Name:  ${secret_name}";
      echo -e "GitHub Secret Value: ${secret_value}";
      echo -e "GitHub Secret (encrypted): ${encrypted}";
      echo -e "\nCreating GitHub Secret: ...";
      echo curl --verbose --silent --request PUT \
           --header "Authorization: token ${github_token}" \
           --header "Accept: ${github_restapi}" \
           https://api.github.com/repos/${github_user}/${github_repo}/actions/secrets/${secret_name} \
           -d '{"encrypted_value":"'${encrypted}'","key_id":"'${github_public_key_id}'"}' ;
    fi;
    curl --verbose --silent --request PUT \
         --header "Authorization: token ${github_token}" \
         --header "Accept: ${github_restapi}" \
         https://api.github.com/repos/${github_user}/${github_repo}/actions/secrets/${secret_name} \
         -d '{"encrypted_value":"'${encrypted}'","key_id":"'${github_public_key_id}'"}' ;
         ## 2>&1>/dev/null ;
    return 0;
  }; alias create-github-secret='create_github_secret';
  ## create-github-secret --secret-name=AWS_ACCESS_KEYPAIR \
  ##                      --secret-value="$(IFS=$'\n'; cat ~/.ssh/private/default-terraform)" \
  ##                      --github-token=${github_personal_token} \
  ##                      --github-user=emvaldes \
  ##                      --github-repo=terraform-awscloud \
  ##                      --verbose ;
```

**<span style="color:red">04</span>** -) Injecting all the required secrets into the target GitHub Repository.

```shell
## Resetting AWS Shared Credentials-file:
export AWS_SHARED_CREDENTIALS_FILE=~/.aws/credentials ;
unset AWS_SESSION_TOKEN AWS_TOKEN_EXPIRES;
## Extract ~/.aws/credentials
amazon-credentials ${AWS_TARGET_PROFILE} verbose;
declare -a default_secrets=(
    AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
    AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
    AWS_DEFAULT_ACCOUNT=${AWS_ACCOUNT}
    AWS_DEFAULT_PROFILE=default
    AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
    DEVOPS_ACCOUNT_ID=?
    DEVOPS_ACCOUNT_NAME=${DEVOPS_ACCOUNT_NAME}
    AWS_DEPLOY_TERRAFORM=true
    AWS_DESTROY_TERRAFORM=true
    INSPECT_DEPLOYMENT=true
    UPDATE_PYTHON_LATEST=true
    UPDATE_SYSTEM_LATEST=true
    DEVOPS_ACCESS_POLICY=${DEVOPS_ACCESS_POLICY}
    DEVOPS_ACCESS_ROLE=${DEVOPS_ACCESS_ROLE}
  );
for xsecret in ${default_secrets[@]}; do
  export GITHUB_SECRET_NAME="${xsecret%%\=*}";
  export GITHUB_SECRET_VALUE="${xsecret##*\=}";
  create-github-secret \
    --secret-name=${GITHUB_SECRET_NAME} \
    --secret-value="${GITHUB_SECRET_VALUE}" \
    --github-user=${DEVOPS_GITHUB_USER} \
    --github-repo=${DEVOPS_GITHUB_REPO} \
    --github-token=${github_personal_token}
done;
```

**<span style="color:red">05</span>** -) Populating the AWS Access Key-Pair (Warning: I have to test if it really works!):

```shell
> create-github-secret --secret-name=AWS_ACCESS_KEYPAIR \
                       --secret-value="$(IFS=$'\n'; cat ${AWS_PRIVATE_SSHKEY})" \
                       --github-user=${DEVOPS_GITHUB_USER} \
                       --github-repo=${DEVOPS_GITHUB_REPO} \
                       --github-token=${github_personal_token} \
                       --verbose ;

DevOps GitHub User:  emvaldes
DevOps GitHub Repo:  terraform-awscloud
GitHub Repos Token:  590b0...b0635
GitHub RESTAPI App:  application/vnd.github.v3+json
GitHub Public Key:   GDAjE...OxiQ=
GitHub Secret Name:  AWS_ACCESS_KEYPAIR
GitHub Secret Value: -----BEGIN OPENSSH PRIVATE KEY-----
b3Blb...2gtcn
-----END OPENSSH PRIVATE KEY-----
GitHub Secret (encrypted): YCnJV...Etw==

Creating GitHub Secret: ...

curl --verbose \
     --silent \
     --request PUT \
     --header Authorization: token 590b0...b0635 \
     --header Accept: application/vnd.github.v3+json \
     https://api.github.com/repos/emvaldes/terraform-awscloud/actions/secrets/AWS_ACCESS_KEYPAIR \
     -d {"encrypted_value":"YCnJV...Etw==","key_id":"568..."}

* Uses proxy env variable no_proxy == 'localhost,127.0.0.1'
*   Trying 140.82.112.6...
* TCP_NODELAY set
* Connected to api.github.com (140.82.112.6) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/cert.pem
  CApath: none
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: C=US; ST=California; L=San Francisco; O=GitHub, Inc.; CN=*.github.com
*  start date: Jun 22 00:00:00 2020 GMT
*  expire date: Aug 17 12:00:00 2022 GMT
*  subjectAltName: host "api.github.com" matched cert's "*.github.com"
*  issuer: C=US; O=DigiCert Inc; OU=www.digicert.com; CN=DigiCert SHA2 High Assurance Server CA
*  SSL certificate verify ok.
> PUT /repos/emvaldes/terraform-awscloud/actions/secrets/AWS_ACCESS_KEYPAIR HTTP/1.1
> Host: api.github.com
> User-Agent: curl/7.64.1
> Authorization: token 590b0e21df0fa70240a47aa4ceac31e362eb0635
> Accept: application/vnd.github.v3+json
> Content-Length: 4636
> Content-Type: application/x-www-form-urlencoded
> Expect: 100-continue
>
< HTTP/1.1 100 Continue
* We are completely uploaded and fine
< HTTP/1.1 204 No Content
< Server: GitHub.com
< Date: Wed, 26 Aug 2020 19:21:54 GMT
< Status: 204 No Content
< X-OAuth-Scopes: admin:enterprise, admin:gpg_key, admin:org, admin:org_hook, admin:public_key, admin:repo_hook, delete:packages, delete_repo, gist, notifications, read:packages, repo, user, workflow, write:discussion, write:packages
< X-Accepted-OAuth-Scopes:
< X-GitHub-Media-Type: github.v3; format=json
< X-RateLimit-Limit: 5000
< X-RateLimit-Remaining: 4990
< X-RateLimit-Reset: 1598472055
< Access-Control-Expose-Headers: ETag, Link, Location, Retry-After, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval, X-GitHub-Media-Type, Deprecation, Sunset
< Access-Control-Allow-Origin: *
< Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
< X-Frame-Options: deny
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin
< Content-Security-Policy: default-src 'none'
< Vary: Accept-Encoding, Accept, X-Requested-With
< X-GitHub-Request-Id: CF63:3F78:360AB:90224:5F46B651
<
* Connection #0 to host api.github.com left intact
* Closing connection 0
```

**<span style="color:red">a</span>** -) How to query the GitHub Secrets to confirm that a particular secret was created (testing):

```shell
$ curl --silent \
       --header "Authorization: token ${github_personal_token}" \
       --header "Accept: ${github_restapi_application}" \
       https://api.github.com/repos/${DEVOPS_GITHUB_USER}/${DEVOPS_GITHUB_REPO}/actions/secrets/${SECRET_NAME} ;
```

```json
{
  "name": "{{ SECRET_NAME }}",
  "created_at": "2020-08-22T18:50:43Z",
  "updated_at": "2020-08-22T18:50:43Z"
}
```

**<span style="color:red">b</span>** -) How to query the GitHub Secrets to delete a particular secret:

```shell
$ curl --silent \
       --request DELETE \
       --header "Authorization: token ${github_personal_token}" \
       --header "Accept: ${github_restapi_application}" \
       https://api.github.com/repos/${DEVOPS_GITHUB_USER}/${DEVOPS_GITHUB_REPO}/actions/secrets/${SECRET_NAME} ;
```

**Note**: If you query a non-existing GitHub Secret, the result will be an empty JSON object.

This is the process I would want to use so GitHub Secrets can be recycled and the application is not aware of these updates.<br>
Since the process is leveraging the AWS STS Assume Role capabilities, both GitHub Secrets and Service Accounts are fully decoupled.

---

#### function [configure_assumerole](https://github.com/emvaldes/devops-tools/blob/e6454b2acaee412f32fc40ef4595dbcf0311749a/functions/devops-awscli.functions#L230)

**Note**: Make sure that the **AWS_DEFAULT_ACCOUNT** is populated with your own AWS Account.

**<span style="color:red">06</span>** -) Generate a JSON file to define the AWS IAM Policy **DevOps--Custom-Access.Policy** <br>
The Service-Account (terraform) privileges in this policy will be attached to the AWS IAM Role **DevOps--Custom-Access.Role**

**Note**: I will start monitoring this service account's behavior (***terraform***) and accordingly restrict its privileges based on what is actually **required**.

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
            "Sid": "StmtCloudWatch",
            "Effect": "Allow",
            "Action": "cloudwatch:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtAutoScaling",
            "Effect": "Allow",
            "Action": "autoscaling:*",
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
        },
        {
            "Sid": "StmtSTS",
            "Effect": "Allow",
            "Action": [
                "sts:*"
            ],
            "Resource": "*"
        }
    ]
}
BLOCK
```

**<span style="color:red">07</span>** -) Create the AWS IAM Policy **DevOps--Custom-Access.Policy**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
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

**<span style="color:red">08</span>** -) Generate a JSON file to define the AWS IAM Policy **DevOps--Custom-Access.Policy**
This will allow and deny privileges that could be attempted to be self-granted.
e.g.: Administrator Access, etc. This policy will be attached to the AWS IAM Role **DevOps--Custom-Access.Role**

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
            "Sid": "StmtEC2",
            "Action": "ec2:*",
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Sid": "StmtELB",
            "Effect": "Allow",
            "Action": "elasticloadbalancing:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtCloudWatch",
            "Effect": "Allow",
            "Action": "cloudwatch:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtAutoScaling",
            "Effect": "Allow",
            "Action": "autoscaling:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtIAM",
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
                        "sts.amazonaws.com",
                        "transitgateway.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Sid": "StmtS3",
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        },
        {
            "Sid": "StmtSTS",
            "Effect": "Allow",
            "Action": [
                "sts:*"
            ],
            "Resource": "*"
        }
    ]
}

BLOCK
```

**<span style="color:red">09</span>** -) Create the IAM Policy **Devops--Permission-Boundaries.Policy**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
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

**<span style="color:red">10</span>** -) Create the AWS IAM Group **devops**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-group \
    --group-name ${DEVOPS_ACCOUNT_GROUP} ;
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

**<span style="color:red">11</span>** -) Create the AWS IAM User **terraform**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-user \
    --user-name ${DEVOPS_ACCOUNT_NAME} ;
```

```json
{
    "User": {
        "Path": "/",
        "UserName": "terraform",
        "UserId": "***",
        "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}",
        "CreateDate": "2020-08-17T06:26:16+00:00"
    }
}
```

**<span style="color:red">12</span>** -) Generate the **terraform** User's AWS IAM Access Keys:<br>
**Note**: This user's AWS IAM Access Key will be exported as environment variables (**AWS_ACCESS_KEY_ID**, **AWS_SECRET_ACCESS_KEY**):

```shell
declare -a session_items=(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY);
declare -a iamuser_accesskeys=($(
    aws --profile ${AWS_DEFAULT_PROFILE} \
        --region ${DEFAULT_REGION} \
        iam create-access-key \
        --user-name ${DEVOPS_ACCOUNT_NAME} \
        --query 'AccessKey.{aki:AccessKeyId,sak:SecretAccessKey}' \
        --output text
  ));
counter=0; for xkey in "${iamuser_accesskeys[@]}"; do
  echo -e "AWS Crendential :: ${session_items[${counter}]} = ${xkey}";
  eval "export ${session_items[${counter}]}=${xkey}";
  ((counter++));
done;
```

**<span style="color:red">13</span>** -) Construct the AWS CLI Credentials file core-structure:<br>
**Note**: The default path for the **${AWS_SHARED_CREDENTIALS_FILE}** is set to ***${HOME}/.aws/credentials***

```shell
mkdir -p ${HOME}/.aws/access/${AWS_DEFAULT_ACCOUNT}/;
target_credfile="${HOME}/.aws/access/${AWS_DEFAULT_ACCOUNT}/${AWS_TARGET_PROFILE}.credentials";
echo -e "[${AWS_TARGET_PROFILE}]
aws_access_key_id = ${AWS_ACCESS_KEY_ID}
aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}
aws_session_token =
x_principal_arn = arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${DEVOPS_ACCOUNT_NAME}
x_security_token_expires =
" > ${target_credfile};
```

**<span style="color:red">14</span>** -) Attach the AWS IAM User **terraform** to the AWS IAM Group **devops**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam add-user-to-group \
    --user-name ${DEVOPS_ACCOUNT_NAME} \
    --group-name ${DEVOPS_ACCOUNT_GROUP} ;
```

**<span style="color:red">15</span>** -) Fetch & Display the AWS IAM Group **devops** configuration:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam get-group \
    --group-name ${DEVOPS_ACCOUNT_GROUP} ;
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "terraform",
            "UserId": "***",
            "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}",
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

**<span style="color:red">16</span>** -) Dynamically generate the AWS IAM Role **DevOps--Custom-Access.Role** granting the Service Account **terraform** the **sts:AssumeRole** capabilities.

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam create-role \
    --path / \
    --role-name ${DEVOPS_ACCESS_ROLE} \
    --max-session-duration 3600 \
    --description "DevOps Infrastructure Deployment - Automation Services." \
    --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${DEVOPS_ACCOUNT_NAME}\"]},\"Action\":[\"sts:AssumeRole\"]}]}" ;
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
                            "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}"
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
**<span style="color:red">17</span>** -) Attach the AWS IAM Policy **DevOps--Custom-Access.Policy** to the AWS IAM Role **DevOps--Custom-Access.Role**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam attach-role-policy \
    --role-name ${DEVOPS_ACCESS_ROLE} \
    --policy-arn arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:policy/${DEVOPS_ACCESS_POLICY} ;
```

**<span style="color:red">18</span>** -) Fetch & Display the AWS IAM Role **DevOps--Custom-Access.Role**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
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
                        "AWS": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}"
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

**<span style="color:red">19</span>** -) Fetch & Display the AWS IAM Role **DevOps--Custom-Access.Role** attached policies:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
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
**<span style="color:red">20</span>** -) Attach the AWS IAM Policy **Devops--Permission-Boundaries.Policy** to the AWS IAM Role **DevOps--Custom-Access.Role**.

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam put-role-permissions-boundary \
    --permissions-boundary arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:policy/${DEVOPS_CUSTOM_BOUNDARY} \
    --role-name ${DEVOPS_ACCESS_ROLE};
```

**<span style="color:red">21</span>** -) Generate a JSON file to define the AWS IAM Policy **DevOps--Assume-Role.Policy** that specifies the AWS IAM Role **DevOps--Custom-Access.Role** to be assumed by the Service Account **terraform**.

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

**<span style="color:red">22</span>** -) Create the AWS IAM Policy **DevOps--Assume-Role.Policy**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
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

**<span style="color:red">23</span>** -) Attach this AWS IAM Policy **DevOps--Assume-Role.Policy** to the AWS IAM Group **devops**:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam attach-group-policy \
    --policy-arn arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:policy/${DEVOPS_ASSUME_POLICY} \
    --group-name ${DEVOPS_ACCOUNT_GROUP};
```

**<span style="color:red">24</span>** -) Fetch & Display the AWS IAM Role **DevOps--Assume-Role.Policy** attached policies:

```shell
aws --profile ${AWS_DEFAULT_PROFILE} \
    --region ${DEFAULT_REGION} \
    iam list-attached-group-policies \
    --group-name ${DEVOPS_ACCOUNT_GROUP};
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

**<span style="color:red">25</span>** -) Reasign the **${AWS_SHARED_CREDENTIALS_FILE}** to activate this custom credentials file **${HOME}/.aws/access/${AWS_DEFAULT_ACCOUNT}/${DEFAULT_PROFILE}.credentials**

```shell
export AWS_SHARED_CREDENTIALS_FILE="${target_credfile}";
```

#### function [amazon_assumerole](https://github.com/emvaldes/devops-tools/blob/e6454b2acaee412f32fc40ef4595dbcf0311749a/functions/devops-awscli.functions#L76)

**Note**: This is an excerpt of the function describe above.

```shell
declare -a session_token=($(
    aws --profile ${AWS_TARGET_PROFILE} \
        --region ${DEFAULT_REGION} \
        sts assume-role \
        --role-arn arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:role/${DEVOPS_ACCESS_ROLE} \
        --role-session-name "${session}-$(date +"%Y%m%d%H%M%S")" \
        --duration-seconds ${DEFAULT_ROLEDURATION} \
        --query 'Credentials.{aki:AccessKeyId,sak:SecretAccessKey,stk:SessionToken,sts:Expiration}' \
        --output text
  ));
counter=0; for xkey in "${session_token[@]}"; do
  eval "export ${AWS_CREDENTIALS_TOKENS[$((counter++))]}=${xkey}";
done;
```

**<span style="color:red">26</span>** -) The Service-Account (terraform) Identity will reflect the current state. <br>
Using the its default AWS IAM User's credentials and not the AWS IAM Role **DevOps--Custom-Access.Role** that was just assumed.

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    sts get-caller-identity ;
```

```json
{
    "UserId": "***",
    "Account": "{{ AWS_DEFAULT_ACCOUNT }}",
    "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}"
}
```
**<span style="color:red">27</span>** -) Once this AWS IAM Role is assumed then these new credentials will need to be stored so they become permanently active at both the environment and file level into a custom credentials file.

```shell
declare -a credentials=(
    aws_access_key_id~${AWS_ACCESS_KEY_ID}
    aws_secret_access_key~${AWS_SECRET_ACCESS_KEY}
    aws_session_token~${AWS_SESSION_TOKEN}
    x_security_token_expires~${AWS_TOKEN_EXPIRES}
    x_principal_arn~arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${AWS_TARGET_PROFILE}
  );
for credential in ${credentials[@]}; do
  sed -i '' -e "s|^\(${credential%\~*}\)\( =\)\(.*\)$|\1\2 ${credential#*\~}|g" ${AWS_SHARED_CREDENTIALS_FILE} ;
done;

cat ${AWS_SHARED_CREDENTIALS_FILE} ;
```

**<span style="color:red">28</span>** -) Attempting to identify the User's (caller) Identity this time will reflect the assumed AWS IAM Role **DevOps--Custom-Access.Role** is applied:


```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    sts get-caller-identity ;
```

```json
{
    "UserId": "***:TerraformPipeline-20200818174647",
    "Account": "{{ AWS_DEFAULT_ACCOUNT }}",
    "Arn": "arn:aws:sts::{{ AWS_DEFAULT_ACCOUNT }}:assumed-role/{{ DEVOPS_ACCESS_ROLE }}/TerraformPipeline-20200818174647"
}
```

**Note**: This approach allows to dynamically assign the AWS IAM Role **DevOps--Custom-Access.Role** to any session by configuring the **${AWS_SHARED_CREDENTIALS_FILE}**.

**<span style="color:red">29</span>** -) Identifying the current value for the **${AWS_SHARED_CREDENTIALS_FILE}**:

```shell
echo -e "Current Credentials file: ${AWS_SHARED_CREDENTIALS_FILE}";
## ~/.aws/access/{{ AWS_DEFAULT_ACCOUNT}}/{{ AWS_COMPANY_NAME}}-{{ AWS_TARGET_PROFILE }}.credentials
```

**<span style="color:red">30</span>** -) Resetting the **${AWS_SHARED_CREDENTIALS_FILE}**:

```shell
export AWS_SHARED_CREDENTIALS_FILE="${HOME}/.aws/credentials";
```

**<span style="color:red">31</span>** -) Exporting the target-profile's AWS Access Key-Pair to all available AWS Regions:

#### function [amazon_keypair](https://github.com/emvaldes/devops-tools/blob/e6454b2acaee412f32fc40ef4595dbcf0311749a/functions/devops-awscli.functions#L174)

```shell
amazon_keypair ${AWS_COMPANY_NAME}-${AWS_MASTER_USER} ${AWS_PUBLIC_SSHKEY} ${DEVOPS_ACCOUNT_NAME} ;
```

---

# Demonstration:

**<span style="color:red">32</span>** -) Exporting the target-profile's AWS Credentials as the current|active environment variables:

```shell
amazon-assumerole ${AWS_TARGET_PROFILE} terraform TerraformPipeline verbose ;
-rw-r--r--  1 emvaldes  staff  235 Aug 18 17:46 /Users/emvaldes/.aws/access/{{ AWS_DEFAULT_ACCOUNT }}/terraform.credentials

[{{ AWS_TARGET_PROFILE }}]
aws_access_key_id = ***
aws_secret_access_key = ***
aws_session_token = IQoJb3JpZ2...OA5ZfYCw==
x_principal_arn = arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}
x_security_token_expires = 2020-08-19T01:46:48+00:00
```

**<span style="color:red">33</span>** -) Confirming that the current AWS Target-Profile is capable of performing specific operations only allowed to it once it has succesfully assumed the intended role:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
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
            "Arn": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}",
            "CreateDate": "2020-08-17T06:26:16+00:00"
        }
    ]
}
```

**<span style="color:red">34</span>** -) We can identify the availability of leased-time for this Service-Account user's AWS Assumed Role:

#### function [assumedrole-timeframe](https://github.com/emvaldes/devops-tools/blob/e6454b2acaee412f32fc40ef4595dbcf0311749a/functions/devops-awscli.functions#L24)

```shell
assumedrole-timeframe ${AWS_TARGET_PROFILE} verbose ;

Token Expires: 2020-08-19 01:46:48 [1597801608]
 Current Date: 2020-08-19 00:47:03 [1597798023]

The Assumed-Role Session has 59 minutes remaining until it expires.
```

---

Please, make sure your **AWS IAM Policy** allows for something like this and enforce the appropriate ***User Permissions Boundary***:

**<span style="color:red">35</span>** -) Identify if AWS S3 Bucket does not exist so it can be created.

```shell
bucket_exists=$(
    aws --profile ${AWS_TARGET_PROFILE} \
        --region ${DEFAULT_REGION} \
        s3api head-bucket \
        --bucket ${AWS_S3BUCKET_NAME} 2>&1
  );
if [[ -n "${bucket_exists}" ]]; then
  create_bucket=$(
      aws --profile ${AWS_TARGET_PROFILE} \
          --region ${DEFAULT_REGION} \
          s3api create-bucket \
          --bucket ${AWS_S3BUCKET_NAME} 2>&1
    );
fi ;
```

**<span style="color:red">36</span>** -) Identify the AWS S3 Bucket's Cannonical Owner-ID:

```shell
export cannonical_ownerid=$(
    aws --profile ${AWS_TARGET_PROFILE} \
        --region ${DEFAULT_REGION} \
        s3api list-buckets \
        --query Owner.ID \
        --output text
  );
```
**<span style="color:red">37</span>** -) Granting full-control to the target AWS S3 Bucket to the AWS S3 Cannonical User:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api put-bucket-acl \
    --bucket ${AWS_S3BUCKET_NAME} \
    --grant-full-control \
    id="${cannonical_ownerid}" ;
```

**<span style="color:red">38</span>** -) Identify the initial AWS S3 Bucket's Access Control List (ACL):

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api get-bucket-acl \
    --bucket ${AWS_S3BUCKET_NAME} ;
```

```json
{
   "Owner": {
       "DisplayName": "***",
       "ID": "***"
   },
   "Grants": [
       {
           "Grantee": {
               "DisplayName": "***",
               "ID": "***",
               "Type": "CanonicalUser"
           },
           "Permission": "FULL_CONTROL"
       }
   ]
}
```

**<span style="color:red">39</span>** -) Configuring this target AWS S3 Bucket ACL's Log-Delivery:

```shell
export logdelivery='http://acs.amazonaws.com/groups/s3/LogDelivery' ;
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api put-bucket-acl \
    --bucket ${AWS_S3BUCKET_NAME} \
    --grant-write URI=${logdelivery} \
    --grant-read-acp URI=${logdelivery} ;
```
**<span style="color:red">40</span>** -) Once again, confirm this target AWS S3 Bucket has the correct ACL configurations:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api get-bucket-acl \
    --bucket ${AWS_S3BUCKET_NAME} ;
```

```json
{
    "Owner": {
        "DisplayName": "***",
        "ID": "***"
    },
    "Grants": [
        {
            "Grantee": {
                "DisplayName": "***",
                "ID": "***",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        },
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
            },
            "Permission": "READ_ACP"
        },
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
            },
            "Permission": "WRITE"
        },
        {
            "Grantee": {
                "DisplayName": "***",
                "ID": "***",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}
```

**<span style="color:red">41</span>** -) Configuring the target AWS S3 Bucket's Logging capabilities:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api put-bucket-logging \
    --bucket ${AWS_S3BUCKET_NAME} \
    --bucket-logging-status \
    '{"LoggingEnabled":{"TargetBucket":"'${AWS_S3BUCKET_NAME}'","TargetPrefix":"logs","TargetGrants":[{"Grantee":{"Type":"AmazonCustomerByEmail","EmailAddress":"'${AWS_EMAIL_ADDRESS}'"},"Permission":"FULL_CONTROL"},{"Grantee":{"Type":"Group","URI":"http://acs.amazonaws.com/groups/global/AllUsers"},"Permission":"READ"}]}}' ;
```

**<span style="color:red">42</span>** -) Confirming that this target AWS S3 Bucket has Logging enabled:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api get-bucket-logging \
    --bucket ${AWS_S3BUCKET_NAME} \
    --query "LoggingEnabled.{TargetPrefix:TargetPrefix,TargetBucket:TargetBucket}" ;
```

```json
{
   "TargetPrefix": "logs",
   "TargetBucket": "{{ AWS_S3BUCKET_NAME }}"
}
```

**<span style="color:red">43</span>** -) Configuring the target AWS S3 Bucket Versioning:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api put-bucket-versioning \
    --bucket "${AWS_S3BUCKET_NAME}" \
    --versioning-configuration Status=Enabled ;
```

**<span style="color:red">44</span>** -) Identify if this AWS S3 Bucket has Versioning enabled:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api get-bucket-versioning \
    --bucket ${AWS_S3BUCKET_NAME} ;
```

```json
{
   "Status": "Enabled"
}
```

**<span style="color:red">45</span>** -) Exporting the target AWS S3 Bucket's LifeCycle configurations as environment variables:

```shell
##  Bucket LifeCycle Configuration variable(s):
export NoncurrentVersionExpiration=425;

##  LifeCycle Non-Current Transitions:
export NoncurrentVersionTransitions_StandardIA=30;
export NoncurrentVersionTransitions_Glacier=60;

##  LifeCycle Rules (Prefix, Expiration):
export RulesPrefix='';
export RulesExpiration=425;

##  LifeCycle Multipart-Uploads (Abort Incomplete):
export AbortIncompleteMultipartUpload=7;

##  LifeCycle Transitions:
export Transitions_StandardIA=30;
export Transitions_Glacier=60;
```

**<span style="color:red">46</span>** -) Configuring the target AWS S3 Bucket's LifeCycle:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api put-bucket-lifecycle-configuration \
    --bucket "${AWS_S3BUCKET_NAME}" \
    --lifecycle-configuration '{"Rules": [{"Status": "Enabled","NoncurrentVersionExpiration": {"NoncurrentDays": '${NoncurrentVersionExpiration}'},"NoncurrentVersionTransitions": [{"NoncurrentDays": '${NoncurrentVersionTransitions_StandardIA}',"StorageClass": "STANDARD_IA"},{"NoncurrentDays":'${NoncurrentVersionTransitions_Glacier}',"StorageClass": "GLACIER"}],"Prefix": "'${RulesPrefix}'","Expiration": {"Days": '${RulesExpiration}'},"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": '${AbortIncompleteMultipartUpload}'},"Transitions": [{"Days": '${Transitions_StandardIA}',"StorageClass": "STANDARD_IA"},{"Days": '${Transitions_Glacier}',"StorageClass": "GLACIER"}],"ID":"'${AWS_S3BUCKET_NAME}'"}]}' ;
```

**<span style="color:red">47</span>** -) Generate a JSON file to define this target AWS S3 Bucket Policy for this Service-Account's privileges:

```console
CONFIG_JSON="/tmp/${AWS_S3BUCKET_NAME}.json";
tee -a ${CONFIG_JSON} <<BLOCK
    "Version": "2012-10-17",
    "Id": "PolicyTerraformS3Bucket",
    "Statement": [
        {
            "Sid": "StmtTerraformS3Bucket",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${AWS_DEFAULT_ACCOUNT}:user/${DEVOPS_ACCOUNT_NAME}"
            },
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::${AWS_S3BUCKET_NAME}/*"
        }
    ]
}

BLOCK
```

**<span style="color:red">48</span>** -) Configuring this target AWS S3 Bucket Policy to enabled protection if it would require to be set as Open to the public:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api put-bucket-policy \
    --bucket ${AWS_S3BUCKET_NAME} \
    --policy file:///${CONFIG_JSON} ;
```

**<span style="color:red">49</span>** -) I would like to recommend that if an AWS S3 Buckets is going to be set as Open to the Public, the AWS CloudFront be the unique AWS S3 Bucket's Principal. This policy could be auto-generated and applied as part of the AWS CloudFront provisioning process.

```
{
    "Version": "2012-10-17",
    "Id": "PolicyforCloudFrontPrivateContent",
    "Statement": [
        {
            "Sid": "CloudFrontOriginAccessIdentity",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity {{ AWS_CLOUDFRONT_ID }}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::{{ AWS_S3BUCKET_NAME }}/*"
        }
    ]
}
```

**<span style="color:red">50</span>** -) Fetching the existing AWS S3 Bucket Policy:

```shell
aws --profile ${AWS_TARGET_PROFILE} \
    --region ${DEFAULT_REGION} \
    s3api get-bucket-policy \
    --bucket ${AWS_S3BUCKET_NAME} \
| tr '\n' ' ' \
| sed -e 's/\([[:space:]]*\)//g' \
      -e 's|\\||g' \
      -e 's|{"Policy":"||g' \
      -e "s|^\(.*\)\(\"}\)$|\1|" \
| python -m json.tool ;
```

```json
{
    "Version": "2012-10-17",
    "Id": "PolicyTerraformS3Bucket",
    "Statement": [
        {
            "Sid": "StmtTerraformS3Bucket",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::{{ AWS_DEFAULT_ACCOUNT }}:user/{{ DEVOPS_ACCOUNT_NAME }}"
            },
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::{{ AWS_S3BUCKET_NAME }}/*"
        }
    ]
}
```

I would strongly recommend that if you are not going to have this AWS S3 Bucket Open to the Public, you lock it down at the AWS S3 Bucket ACL level regardless of the AWS S3 Bucket Policy you might have in place.

Block ALL Bucket public access (bucket settings: ON)
<ol>
<li>Block public access to buckets and objects granted through new access control lists (ACLs)</li>
<li>Block public access to buckets and objects granted through any access control lists (ACLs)</li>
<li>Block public access to buckets and objects granted through new public bucket or access point policies</li>
<li>Block public and cross-account access to buckets and objects through any public bucket or access point policies</li>
</ol>

---

At some point in time, I had a flaw in the process and a set of AWS IAM Access Keys were exposed in the GitHub Repository. I got this automated AWS IAM Inline Policy injected by AWS IAM to protect the user and the account was automatically locked.<br>
I would like to explore this option to make sure that this is part of the default privileges this Service-Account must have.

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

**Reference**: This project is based on the original training materials from [PluralSight](https://www.pluralsight.com).<br />
[Terraform - Getting Started](https://app.pluralsight.com/library/courses/getting-started-terraform) by [Ned Bellavance](https://app.pluralsight.com/profile/author/edward-bellavance)
