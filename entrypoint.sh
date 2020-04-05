#!/bin/bash
source /venv/bin/activate
export FLASK_ENV=development
cd /app
exec flask run --with-threads -h 0.0.0.0 -p 5000