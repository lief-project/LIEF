# Docker file used to compile LIEF on Linux x86-64 compliant with Python tag: manylinux1
# docker build -t liefproject/manylinux1_x86_64:latest -f ./Dockerfile .
FROM quay.io/pypa/manylinux1_x86_64:2020-12-30-e2b3664

RUN yum update -y \
  && yum install -y ccache \
  && yum clean all

RUN /opt/python/cp37-cp37m/bin/pip install cmake==3.13.3 ninja==1.10.0.post2
ENV PATH=$PATH:/opt/python/cp37-cp37m/bin/

RUN curl --output /tmp/gcc-6.3.0-binutils-2.27-x86_64.tar.bz2 -L https://github.com/squeaky-pl/centos-devtools/releases/download/6.3/gcc-6.3.0-binutils-2.27-x86_64.tar.bz2 && \
    echo "ca3e9f92411507018c839c8cc2b496f14956a49fcf6df0cdcb356de7161bcbc5  /tmp/gcc-6.3.0-binutils-2.27-x86_64.tar.bz2" | sha256sum --check --status && \
    tar -C / -xj -f /tmp/gcc-6.3.0-binutils-2.27-x86_64.tar.bz2 && \
    rm -rf /tmp/gcc-6.3.0-binutils-2.27-x86_64.tar.bz2

ENV CC=/opt/devtools-6.3/bin/gcc
ENV CXX=/opt/devtools-6.3/bin/g++
ENV CXXFLAGS="-static-libstdc++ -static-libgcc"

WORKDIR /src
