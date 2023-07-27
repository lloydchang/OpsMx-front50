FROM registry.access.redhat.com/ubi8/ubi:8.3
MAINTAINER sig-platform@spinnaker.io
COPY front50-web/build/install/front50 /opt/front50
RUN yum -y install java-11-openjdk-headless.x86_64 wget vim tzdata-java
RUN adduser spinnaker
RUN mkdir -p /opt/front50/plugins 
RUN chmod -R 777 /opt/front50/plugins/
RUN chown -R spinnaker:spinnaker /opt/
USER spinnaker
CMD ["/opt/front50/bin/front50"]
