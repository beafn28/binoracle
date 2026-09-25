FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends binutils gcc libc6-dev ruby strace ltrace \
    && pip install --no-cache-dir pwntools \
    && gem install one_gadget --no-document \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /w
