##################################################################################
# VARIABLES
##################################################################################

variable "devops_timestamp" {}
variable "devops_engineer" {}
variable "devops_contact" {}
variable "devops_listset" {}
variable "devops_mapset" {}

variable "filebased_parameters" {}

variable "aws_access_key" {}
variable "aws_secret_key" {}

variable "private_keypair_file" {}
variable "private_keypair_name" {}

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

variable "corporate_title" {}
variable "corporate_image" {}

variable "billing_code_tag" {}
variable "bucket_name_prefix" {}

variable "zone_id" {}
variable "domain_name" {}
variable "route53_record" {}

##################################################################################
# LOCALS
##################################################################################
## randint = "${format("%05d",floor(${random_integer.rand.result}))}"
## s3_bucket_name = "${var.bucket_name_prefix}-${local.env_name}-${random_integer.rand.result}"

locals {
  domain_name     = var.domain_name
  route53_record  = var.route53_record
  env_name        = lower(terraform.workspace)
  corporate_title = var.corporate_title
  corporate_image = var.corporate_image
  common_tags = {
    BillingCode = var.billing_code_tag
    Environment = local.env_name
  }
  s3_bucket_name = "${var.bucket_name_prefix}-${local.env_name}-${local.env_index}"
}
