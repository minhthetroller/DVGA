#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$INFRA_DIR/terraform"
REPO_ROOT="$(dirname "$INFRA_DIR")"

cd "$TERRAFORM_DIR"
ecr_app_url=$(terraform output -raw ecr_app_repository_url)
ecr_provisioner_url=$(terraform output -raw ecr_provisioner_repository_url)
aws_region=$(terraform output -raw aws_region)
ecr_registry_url="${ecr_provisioner_url%%/*}"

aws ecr get-login-password --region "$aws_region" | docker login --username AWS --password-stdin "$ecr_registry_url"

cd "$REPO_ROOT"
docker build -t dvga-app .
docker tag dvga-app "$ecr_app_url:latest"
docker push "$ecr_app_url:latest"

docker build -t dvga-provisioner ./provisioner
docker tag dvga-provisioner "$ecr_provisioner_url:latest"
docker push "$ecr_provisioner_url:latest"
