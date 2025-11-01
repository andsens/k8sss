FROM smallstep/step-cli:0.28.7
USER root
RUN apk add --no-cache jq
USER step
