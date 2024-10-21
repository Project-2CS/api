# back-end API


## Steps to run the project:
1. Change Dir to the location of **docker-compose.yml** file
2. Open a Terminal/CMDLine (or in VScode) and run `docker-compose up --build`: in order to build and run the containers (only the first time):
   - which are 2: Database container and django container
   - after building (the first time), you need only to start the containers using this cmd: `docker-compose up`
3. the cmd will install the required stuff and automate some stuff (you need to wait some-minutes because there are some database_checks )
4. after the containers are up (after you see this message **Starting development server at http://0.0.0.0:8000/** , you can start working and the django-web-server will be running on http://localhost:8000
## Notes:
- In order to execute specially related to django there is 2 method:
   1. recommended-way: open a Terminal/CMDLine and run `docker exec -it django_container_id sh`: you will get a shell and execute the cmds you want for example: `python manage.py runserver` or `python manage.py migrate` or installing any python-package using pip
   2. 2nd-method: execute a cmd on the container using docker  : `docker-compose run django ur_cmd_here` for example: `docker-compose run django python manage.py migrate`
- you need to create a virtual env for python packages in order to resolve the imports:
   - Linux: `python -m venv code/venv` create it inside the code folder then `source venv/bin/active` in order to activate the virtual env
   - Windows: in vscode terminal: `python -m venv code/venv` then activiate it using this cmd: `venv\Scripts\activate.bat`

- VsCode extentions to install (if you want to use it for better experience):
   - Dev Containers by microsoft
   - Remote - SSH by microsoft
   - Remote - SSH: Editing Configuration Files by microsoft
   - Remote - Tunnels by microsoft
   - Remote Development by microsoft
   - Remote Explorer by microsoft
