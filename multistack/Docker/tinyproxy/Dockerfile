FROM amazonlinux:2
RUN amazon-linux-extras install -y epel &&\ 
    yum install -y \ 
    tinyproxy &&\
    sed -i '/^Allow 127\.0\.0\.1/a Allow 10\.0\.0\.0\/8' /etc/tinyproxy/tinyproxy.conf &&\
    sed -i '/^Allow 127\.0\.0\.1/a Allow 172\.16\.0\.0\/12' /etc/tinyproxy/tinyproxy.conf &&\
    sed -i '/^Allow 127\.0\.0\.1/a Allow 192\.168\.0\.0\/16' /etc/tinyproxy/tinyproxy.conf &&\
    sed -i '/^Allow 127\.0\.0\.1/a Allow 100\.64\.0\.0\/10' /etc/tinyproxy/tinyproxy.conf &&\
    yum update -y &&\
    yum clean all

EXPOSE 8888

CMD ["tinyproxy", "-d"]