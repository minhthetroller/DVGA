output "ec2_public_ip" {
  description = "Public IP of EC2 instance"
  value       = aws_instance.main.public_ip
}

output "ec2_elastic_ip" {
  description = "Elastic IP address"
  value       = aws_eip.main.public_ip
}

output "ec2_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.main.id
}

output "ssh_private_key" {
  description = "SSH private key for EC2 access"
  value       = tls_private_key.ssh.private_key_pem
  sensitive   = true
}

output "ecr_app_repository_url" {
  description = "ECR repository URL for dvga-app"
  value       = aws_ecr_repository.dvga_app.repository_url
}

output "ecr_provisioner_repository_url" {
  description = "ECR repository URL for dvga-provisioner"
  value       = aws_ecr_repository.dvga_provisioner.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_task_definition_arn" {
  description = "ECS task definition ARN"
  value       = aws_ecs_task_definition.dvga_app.arn
}

output "subnet_ids" {
  description = "Comma-separated public subnet IDs"
  value       = "${aws_subnet.public_1.id},${aws_subnet.public_2.id}"
}

output "ecs_security_group_id" {
  description = "ECS tasks security group ID"
  value       = aws_security_group.ecs_tasks.id
}

output "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  value       = data.aws_route53_zone.main.zone_id
}

output "aws_region" {
  description = "AWS region"
  value       = var.aws_region
}

output "domain" {
  description = "Domain name"
  value       = var.domain
}

output "inactivity_timeout_min" {
  description = "Inactivity timeout in minutes"
  value       = var.inactivity_timeout_min
}

output "max_users" {
  description = "Maximum concurrent users"
  value       = var.max_users
}
