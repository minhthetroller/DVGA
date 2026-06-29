#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$INFRA_DIR/terraform"
ANSIBLE_DIR="$INFRA_DIR/ansible"
AWS_REGION="ap-southeast-1"
S3_BUCKET="dvga-terraform-state"

if ! aws s3api head-bucket --bucket "$S3_BUCKET" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "$S3_BUCKET" \
    --region "$AWS_REGION" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION"
  aws s3api put-bucket-versioning \
    --bucket "$S3_BUCKET" \
    --versioning-configuration Status=Enabled
  echo "Created S3 bucket: $S3_BUCKET"
fi

cd "$TERRAFORM_DIR"
terraform init
terraform apply -auto-approve

ec2_ip=$(terraform output -raw ec2_elastic_ip)
ecr_app_url=$(terraform output -raw ecr_app_repository_url)
ecr_provisioner_url=$(terraform output -raw ecr_provisioner_repository_url)
ecs_cluster_name=$(terraform output -raw ecs_cluster_name)
task_definition_arn=$(terraform output -raw ecs_task_definition_arn)
subnet_ids=$(terraform output -raw subnet_ids)
ecs_security_group_id=$(terraform output -raw ecs_security_group_id)
ssh_private_key=$(terraform output -raw ssh_private_key)
aws_region=$(terraform output -raw aws_region)
domain=$(terraform output -raw domain)
inactivity_timeout_min=$(terraform output -raw inactivity_timeout_min)
max_users=$(terraform output -raw max_users)
ecr_registry_url="${ecr_provisioner_url%%/*}"

SSH_KEY_PATH="$ANSIBLE_DIR/ssh_key"
echo "$ssh_private_key" > "$SSH_KEY_PATH"
chmod 600 "$SSH_KEY_PATH"

echo "Waiting for EC2 SSH to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0
while ! ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "ubuntu@$ec2_ip" "echo ready" 2>/dev/null; do
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
    echo "SSH not ready after $MAX_RETRIES attempts, exiting."
    exit 1
  fi
  echo "Attempt $RETRY_COUNT/$MAX_RETRIES - retrying in 10s..."
  sleep 10
done
echo "EC2 SSH is ready."

cd "$ANSIBLE_DIR"
ansible-playbook -i inventory.yml playbook.yml \
  -e "ec2_ip=$ec2_ip" \
  -e "aws_region=$aws_region" \
  -e "domain=$domain" \
  -e "ecr_app_url=$ecr_app_url" \
  -e "ecr_provisioner_url=$ecr_provisioner_url" \
  -e "ecr_registry_url=$ecr_registry_url" \
  -e "ecs_cluster_name=$ecs_cluster_name" \
  -e "task_definition_arn=$task_definition_arn" \
  -e "subnet_ids=$subnet_ids" \
  -e "ecs_security_group_id=$ecs_security_group_id" \
  -e "inactivity_timeout_min=$inactivity_timeout_min" \
  -e "max_users=$max_users"
