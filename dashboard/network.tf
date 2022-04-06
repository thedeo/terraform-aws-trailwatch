#===============
# VPC Resources
#===============
resource "aws_vpc" "main" {
  cidr_block  = var.cidr
  tags = {
      Name = "${var.project_name}-vpc"
  }
}
 
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
      Name = "${var.project_name}-igw"
  }
}
 
resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = element(var.public_subnets, count.index)
  availability_zone       = element(var.availability_zones, count.index)
  map_public_ip_on_launch = true

  tags = {
      Name = "${var.project_name}-public-${element(var.availability_zones, count.index)}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
      Name = "${var.project_name}-public"
  }
}
 
resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}
 
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)

  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = aws_route_table.public.id
}


#=================
# Security Groups
#=================
resource "aws_security_group" "alb" {
  name   = "${var.project_name}-alb"
  vpc_id = aws_vpc.main.id
 
  ingress {
   protocol         = "tcp"
   from_port        = 80
   to_port          = 80
   cidr_blocks      = var.trusted_cidr
   # ipv6_cidr_blocks = ["::/0"]
  }
 
  ingress {
   protocol         = "tcp"
   from_port        = 443
   to_port          = 443
   cidr_blocks      = var.trusted_cidr
   # ipv6_cidr_blocks = ["::/0"]
  }
 
  egress {
   protocol         = "-1"
   from_port        = 0
   to_port          = 0
   cidr_blocks      = ["0.0.0.0/0"]
   ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
      Name = "${var.project_name}-alb"
  }
}

resource "aws_security_group" "ecs_tasks" {
  depends_on        = [aws_security_group.alb]
  name              = "${var.project_name}-ecs-task"
  vpc_id            = aws_vpc.main.id
 
  ingress {
   protocol         = "tcp"
   from_port        = var.container_port
   to_port          = var.container_port
   security_groups  = [aws_security_group.alb.id]
  }
 
  egress {
   protocol         = "-1"
   from_port        = 0
   to_port          = 0
   cidr_blocks      = ["0.0.0.0/0"]
   ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
      Name = "${var.project_name}-ecs-task"
  }
}

resource "aws_security_group" "codebuild" {
  depends_on        = [aws_security_group.alb]
  name              = "${var.project_name}-codebuild"
  vpc_id            = aws_vpc.main.id
  
  egress {
   protocol         = "-1"
   from_port        = 0
   to_port          = 0
   cidr_blocks      = ["0.0.0.0/0"]
   ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
      Name = "${var.project_name}-codebuild"
  }
}