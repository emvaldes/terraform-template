##################################################################################
# VARIABLES
##################################################################################

variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "private_key_path" {}
variable "key_name" {}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable network_address_space {
  type = map(string)
}
variable "instance_size" {
  type = map(string)
}
variable "subnet_count" {
  type = map(number)
}

variable "instance_count" {
  type = map(number)
}

variable "billing_code_tag" {}
variable "bucket_name_prefix" {}

##################################################################################
# LOCALS
##################################################################################
## randint = "${format("%05d",floor(${random_integer.rand.result}))}"
## s3_bucket_name = "${var.bucket_name_prefix}-${local.env_name}-${random_integer.rand.result}"

locals {
  env_name = lower(terraform.workspace)
  common_tags = {
    BillingCode = var.billing_code_tag
    Environment = local.env_name
  }
  s3_bucket_name = "${var.bucket_name_prefix}-${local.env_name}-${local.env_index}"
}
