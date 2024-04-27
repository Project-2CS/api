#!/bin/sh

# Apply database migrations
echo "Applying database migrations..."
python manage.py makemigrations
python manage.py migrate



# Load data fixtures

echo "Loading data fixtures..."


for fixture_dir in fixtures/*; do
    if [ -d "$fixture_dir" ]; then
        for fixture_file in "$fixture_dir"/*.json; do
            if [ -f "$fixture_file" ]; then
                echo "Loading $fixture_file"
                python manage.py loaddata "$fixture_file"
            fi
        done
    fi
done


echo "Starting Django development server......"
echo "Access it on http://localhost:8000 "
python -u manage.py runserver 0.0.0.0:8000