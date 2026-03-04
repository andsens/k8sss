FROM smallstep/step-cli:0.29.0
USER root
RUN apk add --no-cache jq
# Must stay root to read the hostPath mounted CA key
