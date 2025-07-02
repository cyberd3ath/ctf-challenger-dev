#!/bin/bash

apt install -y ntpdate

ntpdate time.google.com

apt update

apt install -y \
    python3 \
    python3-pip \
    python3-psycopg2 \
    python3-dotenv

pip3 install -r requirements.txt --break-system-packages
