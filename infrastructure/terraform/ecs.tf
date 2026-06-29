resource "aws_ecs_cluster" "main" {
  name = "dvga-cluster"

  tags = {
    Name        = "dvga-cluster"
    Project     = "dvga"
    Environment = "production"
  }
}

resource "aws_cloudwatch_log_group" "dvga_app" {
  name              = "/ecs/dvga-app"
  retention_in_days = 7

  tags = {
    Name        = "dvga-app-logs"
    Project     = "dvga"
    Environment = "production"
  }
}

resource "aws_ecs_task_definition" "dvga_app" {
  family                   = "dvga-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "dvga"
      image     = "${aws_ecr_repository.dvga_app.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = 4280
          hostPort      = 4280
          protocol      = "tcp"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dvga_app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    Name        = "dvga-app-task"
    Project     = "dvga"
    Environment = "production"
  }
}
