aws_access_key   = ""
aws_secret_key   = ""
key_name         = "terraform"
private_key_path = "access/keypair"

bucket_name_prefix = "terraform"
billing_code_tag   = "ACCT8675309"

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
  dev  = 2
  uat  = 2
  prod = 3
}

instance_count = {
  dev  = 2
  uat  = 4
  prod = 6
}
