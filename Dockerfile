FROM python:2.7-alpine

WORKDIR /var/lib/rancher-autoconfig-lb/
ADD src/requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt && python -c "import requests, boto3"

COPY src/ /var/lib/rancher-autoconfig-lb/

ENV AWS_ACCESS_KEY_ID XXXXXXXXX
ENV AWS_SECRET_ACCESS_KEY XXXXXXXX
ENV AWS_ZONE_ID XXXXXXXX
ENV CA https://acme-v01.api.letsencrypt.org/directory
ENV LE_WORK_DIR "/var/lib/rancher-autoconfig-lb/.le"

CMD cd /var/lib/rancher-autoconfig-lb && bash
