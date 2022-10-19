FROM registry.access.redhat.com/ubi8/ubi
MAINTAINER sig-platform@spinnaker.io
COPY front50-web/build/install/front50 /opt/front50
RUN yum -y install java-11-openjdk-headless.x86_64 wget vim
RUN adduser spinnaker
RUN mkdir -p /opt/front50/plugins 
USER spinnaker
CMD ["/opt/front50/bin/front50"]
