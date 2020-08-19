##################################################################################
# OUTPUT
##################################################################################

output "aws_elb_public_dns" {
  value = aws_elb.web.dns_name
}

output "resources_index" {
  value = local.env_index
}

output "cname_record_url" {
  value = "http://${local.route53_record}.${var.domain_name}"
}

output "devops_timestamp" {
  value = var.devops_timestamp
}

output "devops_engineer" {
  value = var.devops_engineer
}

output "devops_contact" {
  value = var.devops_contact
}

output "devops_listset" {
  value = var.devops_listset
}

output "devops_mapset" {
  value = var.devops_mapset
}

output "filebased_parameters" {
  value = var.filebased_parameters
}
