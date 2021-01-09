FROM anthillplatform/anthill-common:latest
WORKDIR /tmp
COPY anthill /tmp/anthill
COPY MANIFEST.in /tmp
COPY setup.py /tmp
RUN pip install .
RUN rm -rf /tmp
ENTRYPOINT [ "python", "-m", "anthill.login.server"]
