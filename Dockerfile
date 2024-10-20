FROM mcr.microsoft.com/azure-functions/python:3.0-python3.7
 
ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true
 
RUN apt-get update && \
    apt-get install -y curl gnupg && \
    curl -sSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
 
 
RUN curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list
 
 
RUN apt-get update && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql17
 
WORKDIR /app
 
COPY  requirement.txt .
 
RUN python -m pip install -r requirement.txt
 
COPY . .
 
CMD func start