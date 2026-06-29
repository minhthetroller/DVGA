variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-1"
}

variable "domain" {
  description = "Domain name for Route53 records"
  type        = string
  default     = "dvga.online"
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "fargate_cpu" {
  description = "CPU units for Fargate task (1 vCPU = 1024)"
  type        = number
  default     = 256
}

variable "fargate_memory" {
  description = "Memory in MB for Fargate task"
  type        = number
  default     = 512
}

variable "inactivity_timeout_min" {
  description = "Inactivity timeout in minutes before stopping Fargate tasks"
  type        = number
  default     = 15
}

variable "max_users" {
  description = "Maximum number of concurrent users"
  type        = number
  default     = 5
}

variable "ec2_key_name" {
  description = "Name for the EC2 key pair"
  type        = string
}


