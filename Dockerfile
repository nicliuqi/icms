FROM openeuler/openeuler:22.03-lts

MAINTAINER nicliuqi<469227928@qq.com>

RUN yum install -y vim wget git xz tar make automake autoconf libtool gcc gcc-c++ kernel-devel libmaxminddb-devel pcre-devel openssl openssl-devel tzdata \
readline-devel libffi-devel python3-devel mariadb-devel python3-pip net-tools.x86_64 iputils libXext libjpeg xorg-x11-fonts-75dpi xorg-x11-fonts-Type1 expect

RUN cd /opt && wget https://github.com/aquasecurity/trivy/releases/download/v0.42.1/trivy_0.42.1_Linux-64bit.tar.gz && \
    tar -zxvf trivy_0.42.1_Linux-64bit.tar.gz && \
    mv ./trivy /usr/local/bin/

WORKDIR /work/icms
COPY . /work/icms
COPY ./deploy/fonts/simsun.ttc /usr/share/fonts
RUN pip3 install -r requirements.txt

RUN cp /usr/bin/python3 /usr/bin/python
ENV LANG=en_US.UTF-8

EXPOSE 8080
ENTRYPOINT ["uwsgi", "--ini", "/work/icms/deploy/production/uwsgi.ini"]
