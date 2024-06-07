package repository

import(
	"context"
	"github.com/lambda-go-auth-apigw/internal/core"
	"github.com/lambda-go-auth-apigw/internal/erro"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

)

func (r *AuthRepository) LoadUserProfile(ctx context.Context, user core.UserProfile) (*core.UserProfile, error){
	childLogger.Debug().Msg("LoadUserProfile")

	var keyCond expression.KeyConditionBuilder

	id := "USER-" + user.ID

	keyCond = expression.KeyAnd(
		expression.Key("ID").Equal(expression.Value(id)),
		expression.Key("SK").BeginsWith(id),
	)

	expr, err := expression.NewBuilder().
							WithKeyCondition(keyCond).
							Build()
	if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrPreparedQuery
	}

	key := &dynamodb.QueryInput{
								TableName:                 r.tableName,
								ExpressionAttributeNames:  expr.Names(),
								ExpressionAttributeValues: expr.Values(),
								KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := r.client.Query(ctx, key)
	if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrQuery
	}

	userProfile := []core.UserProfile{}
	err = attributevalue.UnmarshalListOfMaps(result.Items, &userProfile)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrUnmarshal
    }

	if len(userProfile) == 0 {
		return nil, erro.ErrNotFound
	} else {
		return &userProfile[0], nil
	}
}
