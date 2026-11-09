# build  -> regenerate derived files (index.html, keys.json, ssh.txt, build/keys.txt)
# sign   -> clearsign build/keys.txt into public/keys.txt (YubiKey PIN + touch)
# check  -> fail if public/keys.txt isn't a valid signature over the current build
# deploy -> upload public/ to S3 and invalidate CloudFront
.PHONY: build sign check deploy

build:
	python3 scripts/build.py

sign: build
	gpg --yes --local-user BC4876BDC8AB5AB8C9CB81659497E30583D68D89 \
	    --clearsign --output public/keys.txt build/keys.txt
	@$(MAKE) --no-print-directory check

# Checks both that the signature is valid and that the signed text is exactly
# what build.py generates now, so a stale manifest can't be deployed.
check: build
	@gpg --verify public/keys.txt 2>&1 | grep -q 'Good signature' || { echo "keys.txt: bad or missing signature"; exit 1; }
	@gpg --decrypt public/keys.txt 2>/dev/null | diff -q - build/keys.txt >/dev/null || { echo "keys.txt is stale: run make sign"; exit 1; }
	@echo "keys.txt: signature good and up to date"

deploy: check
	scripts/deploy.sh
