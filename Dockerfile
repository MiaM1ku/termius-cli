FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi-dev \
        libssl-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

ADD . /termius
WORKDIR /termius

RUN pip install -U pip setuptools \
    && pip install -r dev-requirements.txt \
    && pip install -e .

CMD ["pytest", "tests/unit"]
