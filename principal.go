package rbac

type Principal struct {
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	UserID    string `json:"user_id"`
}

type PrincipalInput struct {
	Username string `json:"username"`
}
