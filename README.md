# lambda-go-auth-apigw

POC Lambda for technical purposes

Lambda apigw authorizer for check JWT OAuth 2.0

There is a table user-profile where the lambda get some data from the profile and inject into http headers. 



![Alt text](image.png)

This lambda must be used attached as an authorizer into an ApiGateway

There are 2 types of validation

## Types of validation

### ScopeValidation(token, method, path)

Test, signed validation and all scopes

The scopes are :

      "header.read" : Method header with GET
      "version.read":  Method version with POST
      "info.read": Method info with GET
      "admin": Allowed all access
      "header" Method header with ANY allowed

### TokenValidation(token)

Just test and signed validation the JWT

## Compile lambda

   Manually compile the function

      GOOD=linux GOARCH=amd64 go build -o ../build/main main.go

      zip -jrm ../build/main.zip ../build/main

        aws lambda update-function-code \
        --function-name lambda-go-auth-apigw \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-auth-apigw/build/main.zip \
        --publish

