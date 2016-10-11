FROM python:2.7-alpine

ADD src/* /var/lib/rancher-autoconfig-lb/
RUN cd /var/lib/rancher-autoconfig-lb/ %% pip install -r requirements.txt && python -c 'import requests, boto3'

WORKDIR /var/lib/rancher-autoconfig-lb/

ENV AWS_ACCESS_KEY_ID XXXXXXXXX
ENV AWS_SECRET_ACCESS_KEY XXXXXXXX
ENV AWS_ZONE_ID XXXXXXXX
ENV CA https://acme-v01.api.letsencrypt.org/directory
ENV LE_WORK_DIR "/var/lib/rancher-autoconfig-lb/.le"

CMD python -u run.py
