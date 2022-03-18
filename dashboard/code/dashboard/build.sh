#!/bin/bash
docker build -t dashboard .
docker run -p 80:8000 -e PROJECT_NAME -e REGION -e STATIC_FILES_DOMAIN -e DASHBOARD_DOMAIN -v $HOME/.aws/credentials:/root/.aws/credentials:ro dashboard
# docker run -p 80:8000 dashboard