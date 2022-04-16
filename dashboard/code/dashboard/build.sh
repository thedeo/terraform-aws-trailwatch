#!/bin/bash
docker build -t dashboard .


export PROJECT_NAME='trailwatch'
export ACCOUNT_ID='171336835998'
export REGION='us-east-1'
export DASHBOARD_DOMAIN='dashboard.example.com'
export STATIC_FILES_DOMAIN='dv56hgxxxxx.cloudfront.net'

docker run -p 80:8000 -e PROJECT_NAME -e ACCOUNT_ID -e REGION -e STATIC_FILES_DOMAIN -e DASHBOARD_DOMAIN -v $HOME/.aws/credentials:/root/.aws/credentials:ro dashboard
# docker run -p 80:8000 dashboard