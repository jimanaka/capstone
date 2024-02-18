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
RUN apt update -y && apt install gdb vim git -y
RUN python -m pip install -r requirements.txt
RUN git clone https://github.com/radareorg/radare2
RUN radare2/sys/install.sh
RUN r2pm -U && r2pm -ci r2ghidra

# Set working directory and addour Flask API files
WORKDIR /app
ADD . /app
