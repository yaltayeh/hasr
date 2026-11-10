# Only DNS names: they carry no account ID. ARNs are not output.
output "pq_dns_name" {
  value = aws_lb.pq.dns_name
}

output "default_dns_name" {
  value = aws_lb.default.dns_name
}
