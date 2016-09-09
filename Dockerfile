# r2m2 x Docker
FROM miasm/base
MAINTAINER Guillaume Valadon <guillaume@valadon.net>

# Create the r2m2 user
USER root
RUN useradd r2m2 --home /home/r2m2/

# Install packages, build & install radare2, then remove packages
RUN set -x && \
    PACKAGES="make gcc git python-pip libffi-dev pkg-config python-jinja2" && \
    apt-get update && apt-get install -y $PACKAGES && \
    apt-get remove -y python-cffi && \
    cd /opt && git clone https://github.com/radare/radare2 --depth 1 && \
    cd radare2 && sh sys/install.sh && make symstall

# Copy local files to the container
COPY . /home/r2m2/

# Build & install r2m2
RUN pip install cffi && cd /home/r2m2 && make clean all install

# Do some cleaning
RUN apt-get remove -y $PACKAGES && \
    apt-get autoclean && apt-get --purge -y autoremove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Switch to the r2m2 user    
USER r2m2

# Prepare the environment
ENV LD_LIBRARY_PATH /home/r2m2/
WORKDIR /home/r2m2/
CMD ["r2", "-a", "r2m2", "-"]
