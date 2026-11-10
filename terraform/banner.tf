# Lets the PGP watch (GitHub Actions in bsoyka/sirloin) raise the revocation
# banner on keys.bensoyka.com, and nothing else.
#
# Key decisions:
# - GitHub's OIDC login, not stored AWS keys: only a run of that repo's main
#   branch can assume this role, and only for that run.
# - The OIDC provider already exists in this account (one per account), so it's
#   looked up rather than created; apply fails clearly if it's missing.
# - The role can write exactly one object (status.json) and invalidate the
#   cache. It can't touch keys, certificates or the page itself.

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "banner" {
  name = "keys-revocation-banner"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:bsoyka/sirloin:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "banner" {
  role = aws_iam_role.banner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.site.arn}/status.json"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudfront:CreateInvalidation"]
        Resource = aws_cloudfront_distribution.site.arn
      },
    ]
  })
}

output "banner_role_arn" {
  value = aws_iam_role.banner.arn
}
