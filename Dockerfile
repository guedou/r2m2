# r2m2 x Docker
FROM archlinux/base
MAINTAINER Guillaume Valadon <guillaume@valadon.net>

# Create the r2m2 user
USER root
RUN useradd r2m2 --create-home

# Install packages
RUN set -x && \
    PACKAGES="radare2 git python2-jinja python2-cffi python2-future python2-pip  " && \
    PACKAGES+="make gcc pkg-config bash-bats libunistring gawk grep" && \
    pacman -Sy && pacman -S --noconfirm archlinux-keyring && \
    pacman -S --noconfirm $PACKAGES && \
    ln -s /usr/bin/python2 /usr/bin/python

# Copy local files to the container
COPY . /home/r2m2/
RUN chown -R r2m2:r2m2 /home/r2m2/

# Install miasm
RUN pip2 install -r /home/r2m2/requirements.txt

# Switch to the r2m2 user    
USER r2m2

# Build & install r2m2
RUN cd /home/r2m2 && make all install

# Prepare the environment
WORKDIR /home/r2m2/
ENV PYTHONPATH /home/r2m2/miasm
CMD ["r2", "-a", "r2m2", "-"]
