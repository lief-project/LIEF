FROM quay.io/pypa/manylinux1_x86_64:latest

RUN yum update -y \
  && yum install -y ccache \
  && yum clean all

RUN /opt/python/cp37-cp37m/bin/pip install cmake==3.13.3
ENV PATH=$PATH:/opt/python/cp37-cp37m/bin/

RUN curl -L https://github.com/squeaky-pl/centos-devtools/releases/download/6.3/gcc-6.3.0-binutils-2.27-x86_64.tar.bz2 | tar -C / -xj
ENV CC=/opt/devtools-6.3/bin/gcc
ENV CXX=/opt/devtools-6.3/bin/g++
ENV CXXFLAGS=-static-libstdc++

COPY . /src
WORKDIR /src
