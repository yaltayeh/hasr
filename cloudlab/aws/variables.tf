variable "region" {
  description = "AWS region for the demo."
  type        = string
  default     = "eu-north-1"
}

variable "my_ip" {
  description = "The only source allowed to reach the demo load balancers on 443: the public IP of the machine that runs the scan, as a /32. up.sh sets it as TF_VAR_my_ip from the current public IP; never put it in a committed file, and not in terraform.tfvars, which would override TF_VAR_my_ip."
  type        = string

  validation {
    condition     = can(cidrhost(var.my_ip, 0)) && endswith(var.my_ip, "/32")
    error_message = "my_ip must be a single IPv4 address as a /32."
  }
}

variable "name_prefix" {
  description = "Prefix for resource names; also the value of the Project tag on every resource."
  type        = string
  default     = "hasr-demo"
}
