##################################################################################
# PROVIDERS
##################################################################################

provider "aws" {
  region = var.region
}

##################################################################################
# DATA
##################################################################################

data "aws_availability_zones" "available" {}

data "aws_ami" "aws-linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-hvm*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "template_file" "public_cidrsubnet" {
  count = var.subnet_count[terraform.workspace]

  template = "$${cidrsubnet(vpc_cidr,8,current_count)}"

  vars = {
    vpc_cidr      = var.network_address_space[terraform.workspace]
    current_count = count.index
  }
}

##################################################################################
# RESOURCES
##################################################################################

data "aws_elb_hosted_zone_id" "main" {}

# resource "aws_route53_record" "testing" {
#   zone_id = var.zone_id
#   name    = local.route53_record
#   type    = "A"
#   alias {
#     name                   = aws_elb.web.dns_name
#     zone_id                = data.aws_elb_hosted_zone_id.main.id
#     evaluate_target_health = true
#   }
# }

#Random ID
resource "random_integer" "rand" {
  min = 10000
  max = 99999
}

## Standardize a fixed-sufix for all entities
## Usage: terraform output resources_index
locals {
  env_index = random_integer.rand.result
}

# NETWORKING #
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  name    = "${local.env_name}-vpc-${local.env_index}"
  version = "2.15.0"

  cidr            = var.network_address_space[terraform.workspace]
  azs             = slice(data.aws_availability_zones.available.names, 0, var.subnet_count[terraform.workspace])
  public_subnets  = data.template_file.public_cidrsubnet[*].rendered
  private_subnets = []

  tags = local.common_tags

}

# SECURITY GROUPS #
resource "aws_security_group" "elb-sg" {
  name   = "nginx_elb_sg-${local.env_index}"
  vpc_id = module.vpc.vpc_id

  #Allow HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.env_name}-elb-sg-${local.env_index}" })

}

# Nginx security group
resource "aws_security_group" "nginx-sg" {
  name   = "nginx_sg-${local.env_index}"
  vpc_id = module.vpc.vpc_id

  # SSH access from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP access from the VPC
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.network_address_space[terraform.workspace]]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.env_name}-nginx-sg-${local.env_index}" })

}

# LOAD BALANCER #
resource "aws_elb" "web" {
  name = "${local.env_name}-nginx-elb-${local.env_index}"

  subnets         = module.vpc.public_subnets
  security_groups = [aws_security_group.elb-sg.id]
  instances       = aws_instance.nginx[*].id

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    target              = "TCP:80"
    interval            = 30
  }

  tags = merge(local.common_tags, { Name = "${local.env_name}-elb-${local.env_index}" })

}

# INSTANCES #
resource "aws_instance" "nginx" {
  count                  = var.instance_count[terraform.workspace]
  ami                    = data.aws_ami.aws-linux.id
  instance_type          = var.instance_size[terraform.workspace]
  subnet_id              = module.vpc.public_subnets[count.index % var.subnet_count[terraform.workspace]]
  vpc_security_group_ids = [aws_security_group.nginx-sg.id]
  key_name               = var.private_keypair_name
  iam_instance_profile   = module.bucket.instance_profile.name
  depends_on             = [module.bucket]

  connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ec2-user"
    private_key = file(var.private_keypair_file)

  }

  provisioner "file" {
    content     = <<EOF
access_key =
secret_key =
security_token =
use_https = True
bucket_location = US

EOF
    destination = "/home/ec2-user/.s3cfg"
  }

  provisioner "file" {
    content = <<EOF
/var/log/nginx/*log {
    daily
    rotate 10
    missingok
    compress
    sharedscripts
    postrotate
    endscript
    lastaction
        INSTANCE_ID=`curl --silent http://169.254.169.254/latest/meta-data/instance-id`
        sudo /usr/local/bin/s3cmd sync --config=/home/ec2-user/.s3cfg /var/log/nginx/ s3://${module.bucket.bucket.id}/nginx/$INSTANCE_ID/
    endscript
}

EOF

    destination = "/home/ec2-user/nginx"
  }

  provisioner "file" {
    content = <<EOF
<html>
    <head>
        <title>${local.corporate_title}</title>
    </head>
    <body style="background-color:#000000">
        <p style="text-align: center;">
            <img src="${local.corporate_image}" alt="${local.corporate_title}" style="margin-left:auto;margin-right:auto">
        </p>
    </body>
</html>

EOF

    destination = "/home/ec2-user/index.html"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install nginx -y",
      "sudo service nginx start",
      "sudo cp /home/ec2-user/.s3cfg /root/.s3cfg",
      "sudo cp /home/ec2-user/nginx /etc/logrotate.d/nginx",
      "sudo pip install s3cmd",
      "## s3cmd get s3://${module.bucket.bucket.id}/website/index.html . --force",
      "s3cmd get s3://${module.bucket.bucket.id}/website/${local.corporate_image} . --force",
      "sudo cp /home/ec2-user/index.html /usr/share/nginx/html/index.html",
      "sudo cp /home/ec2-user/${local.corporate_image} /usr/share/nginx/html/${local.corporate_image}",
      "sudo logrotate -f /etc/logrotate.conf"

    ]
  }

  tags = merge(local.common_tags, { Name = "${local.env_name}-nginx-${local.env_index}-${count.index + 1}" })
}

# S3 Bucket config#
module "bucket" {
  name   = local.s3_bucket_name
  source = "./modules/s3"
  # source = "terraform-aws-modules/s3-bucket/aws"
  common_tags = local.common_tags
}
# Error: Unsupported argument
#   on resources.tf line 245, in module "bucket":
#  245:   name = local.s3_bucket_name
# An argument named "name" is not expected here.
# Error: Unsupported argument
#   on resources.tf line 248, in module "bucket":
#  248:   common_tags = local.common_tags
# An argument named "common_tags" is not expected here.


# resource "aws_s3_bucket_object" "website" {
#   bucket = module.bucket.bucket.id
#   key    = "/website/index.html"
#   source = "./website/index.html"
# }

resource "aws_s3_bucket_object" "graphic" {
  bucket = module.bucket.bucket.id
  key    = "/website/${local.corporate_image}"
  source = "./website/${local.corporate_image}"
}
