resource "aws_db_instance" "bad_rds" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "admin"
  password             = "password123!"
  
  publicly_accessible  = true 

  multi_az             = false 
  
  skip_final_snapshot  = true
}

resource "aws_s3_bucket" "bad_s3" {
  bucket = "vulnerable-data-bucket-2026"
}

resource "aws_security_group" "bad_sg" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] 
  }
}