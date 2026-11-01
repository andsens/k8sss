{
	"subject": {
		"commonName": {{ toJson .Subject.CommonName }},
		"organization": {{ toJson .Token.user.groups }}
	},
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["clientAuth"]
}
