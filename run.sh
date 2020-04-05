#!/bin/bash
docker run -it --rm -p 5000:5000 --cap-add NET_ADMIN -v ${PWD}:/app net-fail-lb-assistant:latest