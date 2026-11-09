# Hosting for keys.bensoyka.com: private S3 bucket -> CloudFront (origin access
# control). DNS lives in bsoyka/infra (dns/zones-bensoyka-com.tf), like the other
# CloudFront-backed subdomains (assets, gatekeeper); this module outputs the
# records to put there.
#
# Key decisions:
# - /pki/* is reachable over plain http with no redirect: issued certs point at
#   http://keys.bensoyka.com/pki/*.crl and *.crt, and validators fetch those over
#   http. Everything else redirects to https.
# - WKD isn't hosted here: openpgpkey.bensoyka.com already points at
#   keys.openpgp.org's WKD service (managed in bsoyka/infra).
# - First apply is two-phase because the certificate needs its DNS validation
#   record in bsoyka/infra before CloudFront can use it (see README).

locals {
  host = "keys.bensoyka.com"
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
  versioning_configuration {
    status = "Enabled" # cheap undo for a bad deploy
  }
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
  domain_name       = local.host
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

# Waits until the validation record (output below) exists in bsoyka/infra.
resource "aws_acm_certificate_validation" "site" {
  certificate_arn = aws_acm_certificate.site.arn
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

resource "aws_cloudfront_response_headers_policy" "cors" {
  name = "keys-cors"
  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    origin_override = true
  }
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = local.host
  aliases             = [local.host]
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

  # CRL and CA certificate URLs baked into certificates are plain http.
  ordered_cache_behavior {
    path_pattern           = "/pki/*"
    target_origin_id       = "s3"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = false # serve DER bytes exactly
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
  }

  # Keyoxide fetches the profile from browsers too, so it needs CORS.
  ordered_cache_behavior {
    path_pattern               = "/.well-known/aspe/*"
    target_origin_id           = "s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# ------------------------------------------------------------------ outputs

output "bucket" {
  value = aws_s3_bucket.site.bucket
}

output "distribution_id" {
  value = aws_cloudfront_distribution.site.id
}

# Records for bsoyka/infra dns/zones-bensoyka-com.tf (both DNS-only, not proxied).
output "dns_records" {
  value = {
    validation = [for o in aws_acm_certificate.site.domain_validation_options : {
      name    = trimsuffix(o.resource_record_name, ".")
      type    = o.resource_record_type
      content = trimsuffix(o.resource_record_value, ".")
    }]
    site = { name = local.host, type = "CNAME", content = aws_cloudfront_distribution.site.domain_name }
  }
}
