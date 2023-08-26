package common

type BaseConfig struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type User struct {
	UserName string `json:"user_name"`
	Password string `json:"password,omitempty"`
}
