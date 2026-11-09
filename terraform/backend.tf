terraform {
  backend "s3" {
    bucket       = "bsoyka-tfstate"
    key          = "keys.tfstate"
    region       = "us-east-1"
    use_lockfile = true
  }
}
