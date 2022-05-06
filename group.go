package rbac

import "time"

type GroupList []Group

type Group struct {
	UUID            string    `json:"uuid"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	PrincipalCount  int       `json:"principalCount"`
	PlatformDefault bool      `json:"platform_default"`
	AdminDefault    bool      `json:"admin_default"`
	RoleCount       int       `json:"roleCount"`
	Created         time.Time `json:"created"`
	Modified        time.Time `json:"modified"`
	System          bool      `json:"system"`
}

type GroupInput struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type GroupWithPrincipalAndRoles struct {
	UUID            string      `json:"uuid"`
	Name            string      `json:"name"`
	Description     *string     `json:"description"`
	PlatformDefault bool        `json:"platform_default"`
	AdminDefault    bool        `json:"admin_default"`
	Created         time.Time   `json:"created"`
	Modified        time.Time   `json:"modified"`
	Roles           []Role      `json:"roles"`
	RoleCount       int         `json:"roleCount"`
	System          bool        `json:"system"`
	Principals      []Principal `json:"principals"`
}

type AddUserToGroupInput struct {
	Principals []PrincipalInput `json:"principals"`
}

type AddRoleToGroupInput struct {
	Roles []string `json:"roles"`
}
