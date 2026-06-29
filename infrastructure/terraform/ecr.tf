resource "aws_ecr_repository" "dvga_app" {
  name                 = "dvga-app"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  tags = {
    Name        = "dvga-app"
    Project     = "dvga"
    Environment = "production"
  }
}

resource "aws_ecr_repository" "dvga_provisioner" {
  name                 = "dvga-provisioner"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  tags = {
    Name        = "dvga-provisioner"
    Project     = "dvga"
    Environment = "production"
  }
}
