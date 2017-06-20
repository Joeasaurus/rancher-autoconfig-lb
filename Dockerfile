FROM debian:jessie

MAINTAINER Joe Eaves <joe.eaves@shadowacre.ltd>

RUN apt-get update && apt-get install -y python python-pip vim

WORKDIR /var/lib/rancher-autoconfig-lb/
ADD src/requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt && python -c "import requests, boto3"

COPY src/ /var/lib/rancher-autoconfig-lb/

ENV AWS_ACCESS_KEY_ID XXXXXXXXX
ENV AWS_SECRET_ACCESS_KEY XXXXXXXX
ENV AWS_ZONE_ID XXXXXXXX
ENV CA https://acme-v01.api.letsencrypt.org/directory
ENV LEE_SEED_JSON "{}"
ENV LE_WORK_DIR "/var/lib/rancher-autoconfig-lb/.le"

CMD cd /var/lib/rancher-autoconfig-lb && python -u run.py
