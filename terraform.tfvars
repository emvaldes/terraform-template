aws_access_key = ""
aws_secret_key = ""

private_keypair_file = ""
private_keypair_name = ""

bucket_name_prefix = "terraform"
billing_code_tag   = "ACCT8675309"

corporate_title = "DevOps Team"
corporate_image = "corporate.jpg"

network_address_space = {
  dev  = "10.0.0.0/16"
  uat  = "10.1.0.0/16"
  prod = "10.2.0.0/16"
}

instance_size = {
  dev  = "t2.micro"
  uat  = "t2.small"
  prod = "t2.medium"
}

subnet_count = {
  dev  = 1
  uat  = 2
  prod = 2
}

instance_count = {
  dev  = 1
  uat  = 2
  prod = 4
}

zone_id        = "ZWP6121H1HTKX"
domain_name    = "emvaldes.name"
route53_record = "prototype"

devops_timestamp = "Today Is A Good Day To ..."
devops_engineer  = "DevOps Team"
devops_contact   = "emvaldes@yahoo.com"
devops_listset   = "Proving Nothing"
devops_mapset    = "Testing Something"

filebased_parameters = ""
