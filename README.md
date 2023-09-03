# lambda-go-auth-apigw

POC Lambda for technical purposes

Lambda apigw authorizer for check JWT OAuth 2.0. This lambda must be used attached as an authorizar in ApiGateway

## Compile lambda

   Manually compile the function

      GOOD=linux GOARCH=amd64 go build -o ../build/main main.go

      zip -jrm ../build/main.zip ../build/main

        aws lambda update-function-code \
        --function-name lambda-go-auth-apigw \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-auth-apigw/build/main.zip \
        --publish

## Events

### ScopeValidation(token, method, path)

Test, signed validation and all scopes

### TokenValidation(token)

Just test and signed validation the JWT