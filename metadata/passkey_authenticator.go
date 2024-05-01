package metadata

type PasskeyAuthenticator map[string]PassKeyAuthenticatorAAGUID

type PassKeyAuthenticatorAAGUID struct {
	Name      string `json:"name"`
	IconDark  string `json:"icon_dark"`
	IconLight string `json:"icon_light"`
}
