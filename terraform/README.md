# Hosting

S3 + CloudFront for keys.bensoyka.com. State is in `s3://bsoyka-tfstate/keys.tfstate`,
like bsoyka/infra; Terraform is pinned in the repo's `mise.toml` (`mise install`).
DNS records live in bsoyka/infra, not here.

## First apply (two phases)

The CloudFront certificate needs a DNS validation record before it can be used.

1. `terraform init && terraform apply -target=aws_acm_certificate.site`
2. `terraform output dns_records` (the `validation` entry exists now). Add that
   CNAME to bsoyka/infra `dns/zones-bensoyka-com.tf` (DNS-only) and apply there.
3. `terraform apply`. It waits for validation, then creates CloudFront.
4. `terraform output dns_records` again; add the `site` CNAME (keys.bensoyka.com →
   the CloudFront domain, DNS-only) to bsoyka/infra and apply.

After that, `make deploy` from the repo root uploads the site.
