# Two internet-facing Application Load Balancers that differ only in their TLS
# security policy, plus the read-only IAM role the collector runs as.
#
#   pq       HTTPS 443, ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09
#            (the console default and AWS's recommendation)
#   default  HTTPS 443, no ssl_policy set: the AWS provider, the CLI and
#            CloudFormation then use ELBSecurityPolicy-2016-08
#
# PQ and non-PQ policies cannot share one load balancer, hence two.
# Both answer with a fixed response: no instances, no targets.
# Port 443 is open to var.my_ip only.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

# --- Network: own VPC with two public subnets (an ALB needs two AZs) ---

resource "aws_vpc" "demo" {
  cidr_block           = "10.80.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name_prefix }
}

resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.demo.id
  tags   = { Name = var.name_prefix }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.demo.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(aws_vpc.demo.cidr_block, 8, count.index)
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.demo.id
  tags   = { Name = "${var.name_prefix}-public" }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.demo.id
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# No egress rule: a fixed-response listener never opens a connection.
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "HTTPS from the scanning machine only"
  vpc_id      = aws_vpc.demo.id
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = var.my_ip
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS from the scanning machine"
}

# --- Certificate: self-signed RSA 2048; the private key never enters plan or state ---
# The ephemeral key is passed only to write-only arguments. A new key is generated
# on every run, but the fixed *_wo_version values mean later runs do not re-issue
# or re-import, so the certificate and key in ACM stay a matching pair.
# RSA, so that the 2016-08 policy's RSA key transport suites can be negotiated.

ephemeral "tls_private_key" "demo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "demo" {
  private_key_pem_wo         = ephemeral.tls_private_key.demo.private_key_pem
  private_key_pem_wo_version = 1

  subject {
    common_name = "hasr-demo self-signed test certificate"
  }
  # Both load balancers' DNS names, so the hostname check matches.
  dns_names = [aws_lb.pq.dns_name, aws_lb.default.dns_name]

  validity_period_hours = 168
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]
}

resource "aws_acm_certificate" "demo" {
  certificate_body       = tls_self_signed_cert.demo.cert_pem
  private_key_wo         = ephemeral.tls_private_key.demo.private_key_pem
  private_key_wo_version = 1
  tags                   = { Name = var.name_prefix }
}

# --- Load balancers and listeners ---

resource "aws_lb" "pq" {
  name                       = "${var.name_prefix}-pq"
  load_balancer_type         = "application"
  internal                   = false
  ip_address_type            = "ipv4"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  depends_on                 = [aws_route.internet]
}

resource "aws_lb" "default" {
  name                       = "${var.name_prefix}-default"
  load_balancer_type         = "application"
  internal                   = false
  ip_address_type            = "ipv4"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  depends_on                 = [aws_route.internet]
}

resource "aws_lb_listener" "pq" {
  load_balancer_arn = aws_lb.pq.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
  certificate_arn   = aws_acm_certificate.demo.arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "hasr demo (pq)"
      status_code  = "200"
    }
  }
}

# ssl_policy deliberately not set: this is the "default" that the AWS provider,
# the CLI and CloudFormation give you.
resource "aws_lb_listener" "default" {
  load_balancer_arn = aws_lb.default.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.demo.arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "hasr demo (default)"
      status_code  = "200"
    }
  }
}

# --- Read-only identity for the collector ---
# An IAM role that only this account's AccountFullAccessRole (the project's admin
# role, which runs Terraform) may assume. The ARN is read at plan time, never
# written in the repo.

data "aws_iam_role" "admin" {
  name = "AccountFullAccessRole"
}

resource "aws_iam_role" "hasr_readonly" {
  name                 = "hasr-readonly"
  description          = "Hasr collector: read-only load balancer and certificate inventory"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AdminRoleOnly"
      Effect    = "Allow"
      Principal = { AWS = data.aws_iam_role.admin.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

# The collector's permissions: the committed policy that a bank would also use.
resource "aws_iam_role_policy" "collector" {
  name   = "hasr-collector-readonly"
  role   = aws_iam_role.hasr_readonly.id
  policy = file("${path.module}/../../collectors/aws/iam-policy.json")
}
