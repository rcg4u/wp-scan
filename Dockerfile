# Minimal Dockerfile to run wp-scan in a container
# Usage: docker build -t wp-scan . && docker run --rm wp-scan:latest --help
FROM alpine:3.18
LABEL maintainer="rcg4u"

# Install common tooling used by the script (php-cli is optional for WP-CLI phar)
RUN apk add --no-cache bash coreutils findutils grep sed awk gzip zip jq php-cli curl ca-certificates || true
# ShellCheck is useful for local linting within the container when present
RUN apk add --no-cache shellcheck || true

WORKDIR /opt/wp-scan
COPY . /opt/wp-scan
RUN chmod +x ./wp-scan.sh || true

ENTRYPOINT ["bash", "./wp-scan.sh"]
