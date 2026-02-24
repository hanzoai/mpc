package api

import "context"

type contextKey string

const userContextKey contextKey = "iam_user"

func setUser(ctx context.Context, user *IAMUser) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// GetUser extracts the authenticated IAM user from the request context.
func GetUser(ctx context.Context) *IAMUser {
	user, _ := ctx.Value(userContextKey).(*IAMUser)
	return user
}
