FROM python:3.10.0-alpine3.15
WORKDIR /src
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src src
COPY src database.db
COPY src/app.py /src/
RUN mkdir -p /src/templates
RUN mkdir -p /src/static
RUN mkdir -p /src/static/pics 
COPY src/static/pics/logo__4-removebg.png /src/static/pics
COPY src/static/pics/logo__5-removebg.png /src/static/pics

COPY src/static/dashboard.css /src/static/
COPY src/static/signin.css /src/static/
COPY src/static/starter-template.css /src/static/


COPY src/templates/charts.html /src/templates/
COPY src/templates/dashboard.html /src/templates/
COPY src/templates/ec2.html /src/templates/
COPY src/templates/events_chart.html /src/templates/
COPY src/templates/index.html /src/templates/
COPY src/templates/kms_graph.html /src/templates/
COPY src/templates/login.html /src/templates/
COPY src/templates/sg_graph.html /src/templates/
COPY src/templates/signup.html /src/templates/

EXPOSE 4000
ENTRYPOINT ["python", "app.py"]

RUN echo "from app import db; db.create_all(); exit()" | flask shell
CMD ["sqlite3", "database.db", "select * from user;, .exit"]
