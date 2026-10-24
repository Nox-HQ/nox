resource "aws_s3_bucket" "invoices" {
  bucket = "invoicely-invoices"
  acl    = "public-read"
}
resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_s3_bucket_server_side_encryption_configuration" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
resource "aws_security_group" "db" {
  name = "invoicely-db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  storage_encrypted   = false
  publicly_accessible = true
  username            = "app"
  password            = var.db_password
}
variable "db_password" { sensitive = true }
