# DVGA AWS Deployment Design Spec

## Overview

Deploy the DVGA (Deliberately Vulnerable Go Application) to AWS with per-user isolated containers. Each user gets their own subdomain (`username.dvga.online`) routed through Traefik on a static EC2 instance, with Fargate tasks launched on-demand via a Go provisioning service.

## Architecture

```
Internet
  |
  v
Route53: *.dvga.online + dvga.online -> EC2 Elastic IP
  |
  v
+---------------------------------------------+
|  EC2 Instance (t3.small, ap-southeast-1)    |
|                                             |
|  +-------------+    +-------------------+   |
|  |   Traefik    |    | Provisioning Svc  |   |
|  |  (80, 443)   |    | (Go, port 8080)   |   |
|  |              |    |                   |   |
|  |  ECS Provider|    | - Signup page     |   |
|  |  auto-disc.  |    | - Start/Stop ECS  |   |
|  |  tasks       |    |   Fargate tasks   |   |
|  |              |    | - Inactivity mon. |   |
|  +------+-------+    +--------+----------+   |
+---------+----------------------+-------------+
          |                      |
          v                      v
+---------------------------------------------+
|  ECS Fargate Cluster                        |
|  +----------+ +----------+ +----------+     |
|  | user1:   | | user2:   | | user3:   |     |
|  | DVGA     | | DVGA     | | DVGA     |     |
|  | :4280    | | :4280    | | :4280    |     |
|  | ephemeral| | ephemeral| | ephemeral|     |
|  +----------+ +----------+ +----------+     |
|  ECR: dvga-app + dvga-provisioner images    |
+---------------------------------------------+
```

## Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Routing | Subdomain per user | Clean isolation, wildcard DNS + TLS |
| Container lifecycle | On-demand + inactivity timeout (15 min) | Cost-efficient, data is ephemeral |
| TLS | Let's Encrypt wildcard via Route53 DNS-01 | Free, automated, no ALB needed |
| Traefik discovery | ECS provider (native) | No config file management |
| EC2 bootstrap | Ansible roles | Idempotent, maintainable |
| Data persistence | None (ephemeral) | Fresh instance per session |
| Scale | 1-5 concurrent users, t3.small | Demo/workshop use |
| Region | ap-southeast-1 (Singapore) | User preference |

## Components

### 1. Terraform Infrastructure (`infrastructure/terraform/`)

| File | Resources |
|---|---|
| `main.tf` | AWS provider (ap-southeast-1), backend config |
| `variables.tf` | Region, domain, instance type, Fargate sizing, max users, inactivity timeout |
| `vpc.tf` | VPC, 2 public subnets, IGW, route tables |
| `security-groups.tf` | EC2 SG (80, 443, 8080 inbound), ECS tasks SG (4280 from EC2 SG) |
| `ecr.tf` | ECR repos: `dvga-app`, `dvga-provisioner` |
| `ecs.tf` | ECS cluster `dvga-cluster`, task definition for DVGA app |
| `iam.tf` | EC2 instance role (ECS:RunTask/StopTask/ListTasks/DescribeTasks, ECR:Pull, Route53:ChangeResourceRecordSets, CloudWatch Logs) |
| `ec2.tf` | EC2 t3.small with Elastic IP, key pair, AMI (Ubuntu 22.04) |
| `route53.tf` | Hosted zone `dvga.online`, A records for `dvga.online` and `*.dvga.online` -> Elastic IP |
| `outputs.tf` | ec2_ip, ec2_ssh_key, ecr_app_url, ecr_provisioner_url, ecs_cluster_name |

### 2. Ansible Bootstrap (`infrastructure/ansible/`)

**Roles:**

| Role | Tasks |
|---|---|
| `docker` | Install Docker CE, Docker Compose plugin, add ubuntu to docker group, enable service |
| `ecr-login` | Install AWS CLI if missing, `aws ecr get-login-password | docker login` |
| `deploy` | Create `/opt/dvga/`, template `docker-compose.yml.j2` and `.env.j2`, `docker compose pull`, `docker compose up -d` |

### 3. Traefik Configuration

- **ECS provider** polls `dvga-cluster` for tasks with `traefik.enable=true` tag
- **Wildcard DNS:** `*.dvga.online` A record -> EC2 Elastic IP
- **Wildcard TLS:** Let's Encrypt `*.dvga.online` via DNS-01 challenge (Route53)
- **HTTP -> HTTPS redirect** on entrypoint `web`
- **Routing rule:** `Host('<username>.dvga.online')` per task, set via ECS task tags

### 4. Provisioning Service (`provisioner/`)

**Go HTTP service** managing user container lifecycle.

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Signup page (HTML form) |
| `/signup` | POST | Start Fargate task for username, redirect to subdomain |
| `/status` | GET | JSON list of active users |
| `/health` | GET | Health check |
| `/ping/<username>` | GET | Called by Traefik middleware to track activity |

**Core flow:**
1. User submits username at signup page
2. Validate: alphanumeric, 3-20 chars, not already running, under max_users
3. Call `ECS RunTask` with task tags for Traefik routing
4. Poll until task reaches RUNNING state (~10-15s)
5. Redirect user to `https://<username>.dvga.online`

**Inactivity monitor:**
- Goroutine checks every 2 minutes
- Stops tasks idle > 15 minutes via `ECS StopTask`
- Activity tracked via `/ping/<username>` endpoint (Traefik ForwardAuth middleware)

**State:** In-memory `map[string]UserSession` (username -> task ARN, last activity, creation time). On restart, rebuilds state from `ECS ListTasks`.

### 5. Deployment Scripts (`infrastructure/scripts/`)

| Script | Purpose |
|---|---|
| `deploy.sh` | Orchestrates: `terraform apply` -> extract outputs -> `ansible-playbook` |
| `push-images.sh` | Build + push `dvga-app` and `dvga-provisioner` images to ECR |

### 6. Verification (awscli)

```bash
aws ecs describe-clusters --clusters dvga-cluster
aws ecs list-tasks --cluster dvga-cluster
aws ecr describe-images --repository-name dvga-app
aws route53 list-resource-record-sets --hosted-zone-id <id>
aws ec2 describe-instance-status --instance-ids <id>
curl -s https://dvga.online
curl -s https://testuser.dvga.online
```

## File Structure

```
DVGA/
├── ... (existing app code)
├── provisioner/
│   ├── main.go
│   ├── ecs.go
│   ├── session.go
│   ├── handlers.go
│   ├── templates/
│   │   └── signup.html
│   ├── Dockerfile
│   └── go.mod
├── infrastructure/
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── vpc.tf
│   │   ├── security-groups.tf
│   │   ├── ecr.tf
│   │   ├── ecs.tf
│   │   ├── iam.tf
│   │   ├── ec2.tf
│   │   ├── route53.tf
│   │   └── terraform.tfvars.example
│   ├── ansible/
│   │   ├── ansible.cfg
│   │   ├── inventory.yml
│   │   ├── playbook.yml
│   │   └── roles/
│   │       ├── docker/tasks/main.yml
│   │       ├── ecr-login/tasks/main.yml
│   │       └── deploy/
│   │           ├── tasks/main.yml
│   │           └── templates/
│   │               ├── docker-compose.yml.j2
│   │               └── .env.j2
│   └── scripts/
│       ├── deploy.sh
│       └── push-images.sh
└── docs/superpowers/specs/
    └── 2026-06-29-dvga-aws-deployment-design.md
```
