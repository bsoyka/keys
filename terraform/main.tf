# Hosting for keys.bensoyka.com (+ openpgpkey.bensoyka.com for WKD).
# Private S3 bucket -> CloudFront (origin access control) -> DNS in Cloudflare.
#
# Key decisions:
# - One bucket and one distribution serve both hostnames. WKD's advanced method
#   puts its files under /.well-known/openpgpkey/<domain>/, so the paths can't collide.
# - /pki/* is reachable over plain http with no redirect: issued certs point at
#   http://keys.bensoyka.com/pki/root.crl and root.crt, and validators fetch those
#   over http. Everything else redirects to https.
# - WKD responses carry CORS "*", as the WKD spec asks, so web clients can fetch keys.
# - Cloudflare records are DNS-only (grey cloud). Proxying would put Cloudflare's
#   TLS in front of CloudFront's and can force https on the CRL/AIA URLs.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws        = { source = "hashicorp/aws", version = "~> 6.0" }
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 5.0" }
  }
  # Fill in to match your other projects' state setup, or leave commented for local state.
  # backend "s3" {
  #   bucket = "..."
  #   key    = "keys/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "cloudflare_zone_id" {
  type        = string
  description = "Zone ID for bensoyka.com in Cloudflare"
}

variable "domain" {
  type    = string
  default = "bensoyka.com"
}

provider "aws" {
  region = var.aws_region
  default_tags { tags = { Project = "keys" } }
}

# CloudFront certificates must live in us-east-1 whatever the main region is.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags { tags = { Project = "keys" } }
}

# Reads CLOUDFLARE_API_TOKEN from the environment (needs Zone:DNS:Edit on the zone).
provider "cloudflare" {}

locals {
  keys_host = "keys.${var.domain}"
  wkd_host  = "openpgpkey.${var.domain}"
  hosts     = [local.keys_host, local.wkd_host]
}

# ------------------------------------------------------------------ S3

resource "aws_s3_bucket" "site" {
  bucket_prefix = "bsoyka-keys-"
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "site" {
  bucket = aws_s3_bucket.site.id
  versioning_configuration { status = "Enabled" } # cheap undo for a bad deploy
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.site.arn}/*"
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.site.arn } }
    }]
  })
}

# ------------------------------------------------------------------ TLS

resource "aws_acm_certificate" "site" {
  provider                  = aws.us_east_1
  domain_name               = local.keys_host
  subject_alternative_names = [local.wkd_host]
  validation_method         = "DNS"
  lifecycle { create_before_destroy = true }
}

resource "cloudflare_dns_record" "acm_validation" {
  for_each = {
    for o in aws_acm_certificate.site.domain_validation_options : o.domain_name => o
  }
  zone_id = var.cloudflare_zone_id
  name    = trimsuffix(each.value.resource_record_name, ".")
  type    = each.value.resource_record_type
  content = trimsuffix(each.value.resource_record_value, ".")
  ttl     = 300
  proxied = false
}

resource "aws_acm_certificate_validation" "site" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.site.arn
  validation_record_fqdns = [for r in aws_acm_certificate.site.domain_validation_options : r.resource_record_name]
  depends_on              = [cloudflare_dns_record.acm_validation]
}

# ------------------------------------------------------------------ CloudFront

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_response_headers_policy" "security" {
  name = "Managed-SecurityHeadersPolicy"
}

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "keys-site"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_response_headers_policy" "wkd" {
  name = "keys-wkd-cors"
  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers { items = ["*"] }
    access_control_allow_methods { items = ["GET", "HEAD"] }
    access_control_allow_origins { items = ["*"] }
    origin_override = true
  }
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "keys.${var.domain}"
  aliases             = local.hosts
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  http_version        = "http2and3"

  origin {
    origin_id                = "s3"
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  default_cache_behavior {
    target_origin_id           = "s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security.id
  }

  # CRL and CA cert URLs baked into certificates are plain http.
  ordered_cache_behavior {
    path_pattern           = "/pki/*"
    target_origin_id       = "s3"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = false # serve DER bytes exactly
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
  }

  ordered_cache_behavior {
    path_pattern               = "/.well-known/openpgpkey/*"
    target_origin_id           = "s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = false
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.wkd.id
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# ------------------------------------------------------------------ DNS

resource "cloudflare_dns_record" "hosts" {
  for_each = toset(local.hosts)
  zone_id  = var.cloudflare_zone_id
  name     = each.value
  type     = "CNAME"
  content  = aws_cloudfront_distribution.site.domain_name
  ttl      = 300
  proxied  = false
}

# ------------------------------------------------------------------ outputs

output "bucket" {
  value = aws_s3_bucket.site.bucket
}

output "distribution_id" {
  value = aws_cloudfront_distribution.site.id
}

output "urls" {
  value = [for h in local.hosts : "https://${h}"]
}
