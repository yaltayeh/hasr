# Demo infrastructure for Hasr's AWS cloud discovery. Demo only: state stays
# local on the machine of whoever runs it and is never committed.
terraform {
  # 1.11 is the first release with write-only arguments, which keep the demo
  # certificate's private key out of the plan and state files.
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.72.0" # private_key_wo on aws_acm_certificate since 6.47.0
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= 4.4.2" # ephemeral tls_private_key, private_key_pem_wo on tls_self_signed_cert
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = var.name_prefix
    }
  }
}
