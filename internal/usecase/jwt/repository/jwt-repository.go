package repository

import(
	"context"
	
	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/erro"
	database "github.com/lambda-go-auth-apigw/pkg/database/dynamo"

	"github.com/lambda-go-auth-apigw/pkg/observability"
	"github.com/lambda-go-auth-apigw/internal/model"
	
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
)

var childLogger = log.With().Str("repository", "jwt").Logger()

type RepoJwt struct{
	TableName   *string
	Repository	*database.Database
}

func NewRepoJwt(repository *database.Database,
				tableName   *string) *RepoJwt{
	childLogger.Debug().Msg("NewRepoCredential")

	return &RepoJwt{
		Repository: repository,
		TableName: tableName,
	}
}

func (r *RepoJwt) LoadUserProfile(ctx context.Context, user model.UserProfile) (*model.UserProfile, error){
	childLogger.Debug().Msg("LoadUserProfile")

	span := observability.Span(ctx, "repository.LoadUserProfile")	
    defer span.End()

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
								TableName:                 r.TableName,
								ExpressionAttributeNames:  expr.Names(),
								ExpressionAttributeValues: expr.Values(),
								KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := r.Repository.Client.Query(ctx, key)
	if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrQuery
	}

	userProfile := []model.UserProfile{}
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