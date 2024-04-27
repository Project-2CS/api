FROM python:3.11

ENV PYTHUNBUFFERED=1

WORKDIR /app/

RUN pip install --upgrade pip

COPY ./requirements.txt /app 


RUN pip install --upgrade pip
RUN pip install -r requirements.txt





COPY . /app/

RUN chmod +x /app/entrypoint.sh
ENTRYPOINT [ "sh", "/app/entrypoint.sh" ]

# CMD  chmod +x /app/entrypoint.sh && \
#     /app/entrypoint.sh && 



