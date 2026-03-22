# Deliberately vulnerable Terraform for testing

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls   = false
  block_public_policy = false
  restrict_public_buckets = false
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_ebs_volume" "data" {
  encrypted = false
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_cloudtrail" "trail" {
  enable_logging        = false
  is_multi_region_trail = false
}

variable "db_password" {
  default = "hardcoded-password-123"
}

resource "aws_default_vpc" "default" {}
