FROM oraclelinux:7-slim
RUN yum update -y && \
    yum install -y python-virtualenv iptables make gcc && \
    yum clean all && \
    rm -rf /var/cache/yum
RUN virtualenv /venv
RUN source /venv/bin/activate && \
    pip install --upgrade pip
RUN mkdir -p /app
COPY requirements.txt /app
RUN source /venv/bin/activate && \
    pip install -r /app/requirements.txt

COPY entrypoint.sh /

COPY app.py /app
COPY netconfig.json /app

HEALTHCHECK --interval=15s --timeout=5s \
  CMD curl -f http://127.0.0.1:5000/healthcheck || exit 1

CMD [ "/entrypoint.sh" ]