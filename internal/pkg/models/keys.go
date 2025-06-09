package models

type Keys struct {
	ClientPubKey  string `json:"client_pub_key"`
	ServerPrivKey string `json:"server_priv_key"`
	ServerPubKey  string `json:"server_pub_key"`
}
