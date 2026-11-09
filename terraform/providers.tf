# Credentials come from the usual AWS environment/profile. Everything here is in
# us-east-1, which CloudFront certificates require anyway.
provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = { Project = "keys" }
  }
}
