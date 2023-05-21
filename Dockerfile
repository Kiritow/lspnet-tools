FROM ubuntu:latest
RUN apt update \
  && echo 'tzdata tzdata/Areas select Asia' >> /root/preseed.cfg \
  && echo 'tzdata tzdata/Zones/Asia select Shanghai' >> /root/preseed.cfg \
  && debconf-set-selections /root/preseed.cfg \
  && rm -f /etc/timezone /etc/localtime \
  && DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true apt install -y bird2 \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /tmp/* /var/tmp/* \
  && rm /root/preseed.cfg
RUN mkdir -p /run/bird
ENTRYPOINT ["/usr/sbin/bird", "-d", "-c", "/data/bird.conf"]
