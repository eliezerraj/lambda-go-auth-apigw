# lambda-go-authorizer-cert

lambda-go-authorizer-cert

## Lambda Env Variables

    APP_NAME: lambda-go-autentication-NEW
    OTEL_EXPORTER_OTLP_ENDPOINT: localhost:4317
    REGION:us-east-2
    RSA_BUCKET_NAME_KEY:eliezerraj-908671954593-mtls-truststore
    RSA_FILE_PATH:/
    RSA_PRIV_FILE_KEY:private_key.pem
    CRL_BUCKET_NAME_KEY:eliezerraj-908671954593-mtls-truststore
    CRL_FILE_KEY:crl_ca.pem
    CRL_FILE_PATH:/
    RSA_PUB_FILE_KEY:public_key.pem
    SECRET_JWT_KEY:key-jwt-auth
    SCOPE_VALIDATION:true
    CRL_VALIDATION:true
    TABLE_NAME: user_login_2      
    
## Test Locally

1 Download

    mkdir -p .aws-lambda-rie && curl -Lo .aws-lambda-rie/aws-lambda-rie https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie && chmod +x .aws-lambda-rie/aws-lambda-rie

2 Run

    /local-test$ ./start.sh

3 Invoke

    curl -X POST http://localhost:9000/2015-03-31/functions/function/invocations -d '{"headers":{"authorization":"teste"},"methodArn":"arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info"}'

## Compile lambda

   Manually compile the function

      New Version
      GOARCH=amd64 GOOS=linux go build -o ../build/bootstrap main.go
      zip -jrm ../build/main.zip ../build/bootstrap

        aws lambda update-function-code \
        --region us-east-2 \
        --function-name lambda-go-auth-apigw \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-auth-apigw/build/main.zip \
        --publish

+ Test APIGW

        {
        "headers": {
            "authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJsYW1iZGEtZ28tYXV0ZW50aWNhdGlvbiIsInZlcnNpb24iOiIyIiwiand0X2lkIjoiN2RmZGI4MDctZmU2ZC00NDE2LWE3YTgtZDA3NmRiM2ZlYTc1IiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTczMzU0MDE2OX0.BFpRsLG26M_q_edK0RhtoMGibViupmEZJuQv1Nnqa2k"
        },
        "methodArn": "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info"
        }