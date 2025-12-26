#!/bin/bash

# https://ssorc.tw/10205/centos-7-keeps-to-use-yum/
sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo; \
    sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo; \
    sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo; \
    yum install -y wget make git

GO_VERSION="1.24.7"; \
    cd /usr/local; wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz; \
    tar -zxf go${GO_VERSION}.linux-amd64.tar.gz && rm -f go${GO_VERSION}.linux-amd64.tar.gz;

# for building my modifications
yum install -y gcc libpcap-devel; LZ4_VERSION="r126"; \
    cd /tmp; wget https://github.com/lz4/lz4/archive/refs/tags/${LZ4_VERSION}.tar.gz; \
    tar -zxf ${LZ4_VERSION}.tar.gz && rm -f ${LZ4_VERSION}.tar.gz; \
    mv /tmp/lz4-${LZ4_VERSION}/lib/* /usr/local/src/; rm -rf /tmp/lz4-${LZ4_VERSION};
