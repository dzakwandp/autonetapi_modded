FROM ubuntu:bionic
RUN apt update
RUN apt install -y net-tools
RUN apt install -y hping3
RUN apt install -y iputils-ping iputils-tracepath
RUN apt install -y curl wget nano vim
RUN apt install -y python3 python3-pip
RUN pip3 install datetime
RUN pip3 install asyncio
COPY ./*.py /root/
