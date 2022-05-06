package rbac

import "time"

type RoleList []Role

type Role struct {
	UUID            string    `json:"uuid"`
	Name            string    `json:"name"`
	DisplayName     string    `json:"display_name"`
	Description     *string   `json:"description"`
	Access          []Access  `json:"access"`
	Created         time.Time `json:"created"`
	Modified        time.Time `json:"modified"`
	PolicyCount     int       `json:"policyCount"`
	AccessCount     int       `json:"accessCount"`
	Applications    []string  `json:"applications"`
	System          bool      `json:"system"`
	PlatformDefault bool      `json:"platform_default"`
	AdminDefault    bool      `json:"admin_default"`
}

type RoleInput struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description *string  `json:"description"`
	Access      []Access `json:"access"`
}
