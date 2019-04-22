FROM alpine

ADD requirements.txt /code/
WORKDIR /code

ENV TZ America/Sao_Paulo
ENV AWS_DEFAULT_REGION us-east-1

RUN apk add --no-cache tzdata python3 py-cryptography py-lxml py-zmq build-base python3-dev libffi-dev libressl-dev \
    && python3 -m ensurepip \
    && rm -r /usr/lib/python*/ensurepip \
    && pip3 install --upgrade pip setuptools \
    && pip3 install --no-cache-dir -r requirements.txt \
    && rm -r /root/.cache \
    && mkdir /root/.aws/ \
    && echo -e '[default]\nregion = us-east-1' > /root/.aws/config \
    && apk del build-base python3-dev libffi-dev libressl-dev

ADD ./vraptor_libs/ /usr/lib/python3.6/vraptor_libs/
ADD ./vraptor_func/ /usr/lib/python3.6/vraptor_func/
CMD [ "python3", "app.py" ]
