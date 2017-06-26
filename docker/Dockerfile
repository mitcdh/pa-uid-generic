FROM python:2-alpine

ADD pa-uid-generic.py /app/pa-uid-generic/pa-uid-generic.py
RUN pip install peewee pandevice

WORKDIR /app/pa-uid-generic
CMD ["python2", "pa-uid-generic.py"]
