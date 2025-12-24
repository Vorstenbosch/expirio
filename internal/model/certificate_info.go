package	model

type CertificateInfo struct {
	Host           string
	Issuer         string
	ValidFrom      string
	ValidTo        string
	DaysRemaining  int
	Trusted       bool
}