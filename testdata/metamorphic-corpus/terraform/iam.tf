resource "aws_iam_policy" "admin" {
  name = "app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_db_instance" "primary" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  username            = "admin"
  password            = "Sup3rSecretDbPass!"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
