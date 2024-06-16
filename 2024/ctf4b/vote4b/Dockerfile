FROM dreamhackofficial/web3-base:latest@sha256:9c3f148a20a0ad309c400b3fc578a974f82692a33d49b5aa355d664ffc542032

COPY ./src/*.sol /app/src
COPY ./deploy/config.yaml /app/
COPY ./deploy/verifier.py /app/verifier.py
RUN echo "ctf4b{*** REDACTED ***}" > /app/flag.txt

RUN /app/build.sh

EXPOSE 5000
