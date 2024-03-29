# Create our image based on Python 3.8
FROM python:3.11

# RUN apt update -y && apt install net-tools iputils-ping -y

# Expose ports
EXPOSE 5000

# Tell Python to not generate .pyc
ENV PYTHONDONTWRITEBYTECODE 1
# Turn off buffering
ENV PYTHONUNBUFFERED 1

# Install requirements using pip
ADD requirements.txt .
RUN dpkg --add-architecture i386
RUN apt update -y && apt install gdb git libc6:i386 libc6-dbg:i386 libncurses5:i386 wget cmake -y
RUN python -m pip install -r requirements.txt
RUN git config --global http.postBuffer 157286400

# # RIZIN
# RUN git clone --depth 1 https://github.com/rizinorg/rizin /tmp/rizin && \
#   cd /tmp/rizin && \
#   meson setup build && \
#   meson compile -C build && \
#   meson install -C build
#
# RUN mkdir /tmp/rz-pm && \
#   cd /tmp/rz-pm && \
#   wget https://github.com/rizinorg/rz-pm/releases/download/v0.3.3/rz-pm-linux-x86_64 && \
#   chmod +x rz-pm-linux-x86_64 && \
#   ./rz-pm-linux-x86_64 install rz-ghidra
# ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/lib/x86_64-linux-gnu/"
# RUN rm -rf /tmp/rizin /tmp/rz-pm

# RADARE2
RUN git clone https://github.com/radareorg/radare2
RUN radare2/sys/install.sh
RUN r2pm -U && r2pm -ci r2dec

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Set working directory and addour Flask API files
WORKDIR /app
ADD . /app
