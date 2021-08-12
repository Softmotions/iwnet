#!/bin/sh

openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -subj '/CN=localhost'
