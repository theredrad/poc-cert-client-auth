package cert

import (
	"encoding/base64"
	"testing"
)

const (
	caCert2048Str = "MIIDKzCCAhOgAwIBAgIEATTXTTANBgkqhkiG9w0BAQsFADAlMREwDwYDVQQKEwhUZXN0IE9yZzEQMA4GA1UEAxMHVGVzdCBDQTAgFw0yNDAyMDUyMjUzMDlaGA8yMTI0MDExMjIyNTMwOVowJTERMA8GA1UEChMIVGVzdCBPcmcxEDAOBgNVBAMTB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+QW/Is+5px9YpOKfESaqulNOthQHbguRalSAw1ieFW8GRRXDYxzeKxuSYerwa1rrRPbKWxs3eKqBwN0/ws8OUuvqMboxudD6IEoXl+3mtQX86iqm9zEoh78X0UxrEiaQCQikoDMz84na0FFe409xJ2gFH/DbmD/bXQrv00eBN46eKQwO2lOnord8KtEQMWT02dccsmpWT5e0FVD/a8obhf1xrIBTC5idy9cs4x3esoBndV2ivD3KgR6490Z7IsLNpMn0ZrbqvBEwCPms0ox/jriPlUZn5q7TxXlFFeORRC5G/jSaLRyZo+Faxnm8lS9V1/hRsWXfc4gt8ZfpoIYrdAgMBAAGjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUGUB8Xkal4FJ5xBEc7k3r05l1vc4wDQYJKoZIhvcNAQELBQADggEBABnYsrxTWV5cx3apoqydrkC/1OSu13K05RlqN3YwjRSKllbXp0wZq3ohgOszz2SVUlzVMEyqOTYjBDu9q0r4/EKH7oYpUNHIpWnIsbWSl+LSKFTd8XgUjEE7iq+XC1nVn3mceR29TkL3hnL1GqDX8ActixOMXTSUj/YXWlDbA2NfI6p7Ct+OGBU7sDh/CQTbjuSUtCORPaviZV2dT8gxnh5kz3geMoMmZ7ca0nKHYWbQVjPLMdq3bvYrlB2Gpm/CWVUHX6scGzd11Q5imMU/NwENj0bezOyrBABSpmNUcH3060EFG0HaI+xUBLn3pQanoPanKMoP97ewjvvbtyVi+pw="

	clientCert2048Str = "MIIDaDCCAlCgAwIBAgIEeKQaiDANBgkqhkiG9w0BAQsFADAlMREwDwYDVQQKEwhUZXN0IE9yZzEQMA4GA1UEAxMHVGVzdCBDQTAgFw0yNDAyMDUyMjU1MjFaGA8yMTI0MDExMjIyNTUyMVowNDERMA8GA1UEChMIVGVzdCBPcmcxDzANBgNVBAsTBkNsaWVudDEOMAwGA1UEAxMFYWxpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQn2jdBCZzh2/2XDF+5Al6uTKqiC+0XkcPh8tC0/5sZL/v3NmFC1oL5G1ugp62ZjBvvEx0PI5CsP55XdLQvHpZBpx31RF8ymEeb6OCClKdu7ch9Ntsg2CyU2FRvCtSYbWFZA8U/aPZ2Qqz/0HS8IE8Mv90VDEIGXfYMlih76nHpiZprQqAj9IAkuQyQZy3XiM9LawRxCmrykZLDueVYRnlPK+n10qBilSwONyYul+kcWQspNMtM3kE2nt0tdTOV35jhLzuolgNTQDc5LfswadJUhFhn8S2taC5X/et4RX4TVlgvGr59G8aiT+eQoO0AIN8ZA79ne/lL6bExlcFAaBZAgMBAAGjgY4wgYswDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAUBgNVHQ4EDQQLYWxpY2Uta2V5LTEwHwYDVR0jBBgwFoAUGUB8Xkal4FJ5xBEc7k3r05l1vc4wIwYDKgMEBBxib2IudXNlci5yZWFkIGJvYi51c2VyLndyaXRlMA0GCSqGSIb3DQEBCwUAA4IBAQCI/yr2ezN2ILAmnUA/NSsefbkQsf3KwlQ7X9+4GsN5KF7f9i5DQg8KV7/+3Xq4b0gEYQuSj2avwqTC1PlJZPWnsntYdlHtIiFpHjt6P0oNLMSc5m9+k7qOUvSY6e4taS4+lQQhm6RQyMeW1CZWshOIeo1b1YRIfDWAd23CW2Zg0PkJl9/Vm937DNfRVtI6+jM/hUIApl38Krdpuj3k4SACZJkWFkORgEpdPTl3f/h0uu6JhNmqvcvCZSItubHTqM3J4Re97NFD7gyarbkHL3O7a1JIxCeoKZGtStW55h+c1Wy1IhjfMoXle87V9Bo0fjecBjiJPkdky3xTSOyW/0Tq"

	caCert4096Str = "MIIFMzCCAxugAwIBAgIEATTXTTANBgkqhkiG9w0BAQsFADApMQ0wCwYDVQQKEwRUZXN0MRgwFgYDVQQDEw9QcmltYXJ5IFRlc3QgQ0EwIBcNMjQwMjA1MjAzMjE4WhgPMjEyNDAxMTIyMDMyMThaMCkxDTALBgNVBAoTBFRlc3QxGDAWBgNVBAMTD1ByaW1hcnkgVGVzdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOPhPLO1Z5eJ7RxCsD6rzrqmAO4xl8Jq2L+yai5N947qQDHnbXpmRpo7qZsU595RrIMgbKx5gNdzeZk9rGJXmMqW4OEZeSQLtTmP5IagWr1IGAtn6xg+dENTtpgvZqrDyt5+TIX4fPYNtfFWS+0EQLs+nLUxNYvTejJdvRq987WCPvw1LJ3XcLSXQ5QInCnsWMowka3K3JnVjht6MxLcOeLi0KSsHMKmYYrkIxvu6mKLzoCiDqo77oA9hqGQW5g6vKHAQIYCtLwL1rsZyQYEPu8nFFCykVvbTT0PP+whGVq90Rm4OljSMmiZ27aZWf4nPuwGuFV3PrhheojjphxkSwc1cGpkmIvXNrAStKezz7m3iQPVX90Lg9Gcq8yLNkoNGG3YjirIfIbSKO077gZWZrb7SOsH2vXTKFTkI5LwauXLf6v4NjidRrADuedCWEtV98WtZKLc6LmexpKXYWKMdoXHh6UaPYihWhhxrE4wPtrZIiMyp4dQiTxqVDF7/3PPwYdKx9TDSVCcmx19QpGsVpxUBsjk2typCvupZxtNAz+yVSeQsqlYqaNAhgp/q1il9UQPHckckFxbdZzg2rNDxnS1/F5Nl0Ppa8GXPh/I2P/d000LRmwWFCZ+ko7kZZ1nbSwQ21PDMlLEVdAheaGuuK1chGzSifTI5JkG8Jy2c/NjAgMBAAGjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIa7KYjo1DYOF8gnJwnnXp9SWneowDQYJKoZIhvcNAQELBQADggIBAN/W4ictEwx4NC6RwmII9ahJm/lXw/3SBJZsMxyZn6BmKJHb7PjscWUMuLLR3g5enL8RSY5CvDzGwQ9eA0mHFvzvU650ZlKQmmiRda8zHFmXJZWFdOzM3UZ3kANYvEFFYt2pHB1YIVsaGhveLfuaKTwBblRtDeEWOffPqhLqpBt3MvgzvWDrlQfPns52sqxmQsikRFNBKPZJk6s5Ac0MOx0tfyBNzH7IYfGDWPDnz2yyqA+U+0jtfKoLNbXPmx3fUCASomcyGjFLNgypLDzLP7wFnt2tf3I4EnzxAE+OdCAWLG2EnAuUnDLNZKR2biLvTr+CC66QMD6JsWas3s5t3Xe9JHWCo2kkh9NeZDRkP9IEUkWnfc1GBwG+bTS4blKdaXtV/ECmZzfRC48V+jm11O2HyuE5GCMsdfkj5mqWu49/nRIxnF5NPTbZCeZxumwGBnoAmmNF6QNnOfB4FJefvadosV/RDZi1AvrRQi4tZqV1pYubfUVjUoBq7DHHlphHsxkXWG2xQfMahAr/DEzCy4w+kcbyVzysXr9ijXBBUpbqjPNcIY+HQcHzJVXE10G7REFrKi4YPMbd6kAmU0bvdmOKNPokDGo/iTOgHtF4icU4IfGyqf7GaMRbejWitsT2Nfw7gWlmSy66160mZ68cmtythvCQLdrb5hsKCTjM0RBi"

	clientCert4096Str = "MIIFaDCCA1CgAwIBAgIEeKQafjANBgkqhkiG9w0BAQsFADApMQ0wCwYDVQQKEwRUZXN0MRgwFgYDVQQDEw9QcmltYXJ5IFRlc3QgQ0EwIBcNMjQwMjA1MjA0MjU3WhgPMjEyNDAxMTIyMDQyNTdaMDAxDTALBgNVBAoTBFRlc3QxDzANBgNVBAsTBkNsaWVudDEOMAwGA1UEAxMFYWxpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC43IjnteCKyuWpY5rShtITu4SAZ3Gm3cPoPoPEcZ53wvL+zAuxnhvAQZhmKUKg9prhnWo2k/ycparKzW1F88YMf7OxQubNEYf9b+h3W5+JnxgHD+VYfQgw7QijbNqOb63LEZBlKDykM/3Ly0UfMtRN8VEmwldT5W61HOhlWh+4BQxGOr8QTgVysUroTVpedh/yoGoeb9mV85OekG8Nf6YST5vSKcP7dUqsYQICUDVrVslG643g7gcJYyhb2eSLahHGBF+Ugno0w4da+mU5dlrvWIgSWKZ84RPnC8imTvPTwZAiEJQEhp24muLDR7o6Zi8j6yHnbigeTn/bhmQLSEueuqEcHr+YEU5lExRNqlV/bRdthvuxFCBA0++8FrWiXkYHksnEVoyjs3gCKI+aO0QPU3aE9MOxY8mqKsGJxlxyOnsHZ9nuNs0HhwAS7x/Hh0Pku0i7BA3lJtXh9diXMlINs2aqX2ug35Z7SzkcvgmozoK4lGBO7Zvg8XMdFkTf+eipkw4Ao18MwAWNJpi3wRB7whFOf65qK7X+S84ODWv4Pqe0KY52gQqRUcTxw5JuoeDjFTLxBaDWtI40Xrn1xHmC18P/05Eo29woIkCTOOv3OjnxuZwCDtQW4B0GUt954yNHBohT1/HISYJzqKYYW290zaNykZEgBBV3zcJgOoXnFwIDAQABo4GOMIGLMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwFAYDVR0OBA0EC2FsaWNlLWtleS0xMB8GA1UdIwQYMBaAFCGuymI6NQ2DhfIJycJ516fUlp3qMCMGAyoDBAQcYm9iLnVzZXIucmVhZCBib2IudXNlci53cml0ZTANBgkqhkiG9w0BAQsFAAOCAgEAmNme18T3MMF2oS+rpB5XAosyXoBDtUKiCEVrGv+a+dLVZQiRVx51S/a9jXHxbWUMbYbFhFVkUbVm1CnePttPihzdBYL2vxaxqOKlvogWAm/z1qSTQKmdb5ztQNZhUqpw19hsK2CVN93RO+5qn2tjSw0FebohNlDSYJpuMyoJL4Wf38s4rCqY0Y73UiKiTBaw3dQ3Qp2hvUasM3r5miFMYKI7uRLHs++L6L08f79yKRTicHxCzJQJM2wUoyY+Q9AmLO9Zy0n496SdgbZFZiTPWidUmXpdoMR1+G0088uNMGLy+WKkjEtEHd/cCVuL4I1PCGlQGFI9OWLyMdyDlRgUyHUK2ep3MHuvgTmkHNprLc97m64p7Upuah78T3h3HZNbKrOzXHkWBKEudL2Wq8KB6ANcCEZMM0Hj2zxRG9gLYEPG8uZRqq6xg3r6yL9wL5CLk9Ig45cqtAHMad19XdpfX6/vm2+MsAfMQ/9qGQfoR0fwtyd3+Dxk81R45IdldJJpPU6OWkD2DZAgEI/aMRs1CWzVAmGuMlFnybZ6/tLixNkFryKmUO1aEfhdf1AAgINJ44sDsrPXZjEnrarPnlm8nymDVx8OlvPjE+4tPTTgMFxLU7D2f3Ftg2eKnjFTSXej2n5wPJV8TGgnlWJ1nSbvFhZJ2zEdlu24VnYbZh0DjjI="
)

var (
	caCert2048Bytes, _     = base64.StdEncoding.DecodeString(caCert2048Str)
	clientCert2048Bytes, _ = base64.StdEncoding.DecodeString(clientCert2048Str)

	caCert4096Bytes, _     = base64.StdEncoding.DecodeString(caCert4096Str)
	clientCert4096Bytes, _ = base64.StdEncoding.DecodeString(clientCert4096Str)
)

func BenchmarkValidatorValidate2048KeySizeWithDecodeBase64(b *testing.B) {
	caCert, err := DecodeFromDERBytes(caCert2048Bytes)
	if err != nil {
		b.Errorf("expected ca cert, got err: %s", err)
		b.FailNow()
	}

	validator := NewValidator(caCert)

	for i := 0; i < b.N; i++ {
		clientCert2048Bytes, _ = base64.StdEncoding.DecodeString(clientCert2048Str)

		clientCert, err := DecodeFromDERBytes(clientCert2048Bytes)
		if err != nil {
			b.Errorf("expected client cert, got err: %s", err)
			b.FailNow()
		}

		validator.Validate(clientCert)
	}
}

func BenchmarkValidatorValidate2048KeySizeWithDecode(b *testing.B) {
	caCert, err := DecodeFromDERBytes(caCert2048Bytes)
	if err != nil {
		b.Errorf("expected ca cert, got err: %s", err)
		b.FailNow()
	}

	validator := NewValidator(caCert)

	for i := 0; i < b.N; i++ {
		clientCert, err := DecodeFromDERBytes(clientCert2048Bytes)
		if err != nil {
			b.Errorf("expected client cert, got err: %s", err)
			b.FailNow()
		}

		validator.Validate(clientCert)
	}
}

func BenchmarkValidatorValidate2048KeySize(b *testing.B) {
	caCert, err := DecodeFromDERBytes(caCert2048Bytes)
	if err != nil {
		b.Errorf("expected ca cert, got err: %s", err)
		b.FailNow()
	}
	validator := NewValidator(caCert)

	clientCert, err := DecodeFromDERBytes(clientCert2048Bytes)
	if err != nil {
		b.Errorf("expected client cert, got err: %s", err)
		b.FailNow()
	}

	for i := 0; i < b.N; i++ {
		validator.Validate(clientCert)
	}
}

func BenchmarkValidatorValidate4096KeySizeWithDecodeBase64(b *testing.B) {
	caCert, err := DecodeFromDERBytes(caCert4096Bytes)
	if err != nil {
		b.Errorf("expected ca cert, got err: %s", err)
		b.FailNow()
	}

	validator := NewValidator(caCert)

	for i := 0; i < b.N; i++ {
		clientCert4096Bytes, _ = base64.StdEncoding.DecodeString(clientCert4096Str)

		clientCert, err := DecodeFromDERBytes(clientCert4096Bytes)
		if err != nil {
			b.Errorf("expected client cert, got err: %s", err)
			b.FailNow()
		}

		validator.Validate(clientCert)
	}
}

func BenchmarkValidatorValidate4096KeySizeWithDecode(b *testing.B) {
	caCert, err := DecodeFromDERBytes(caCert4096Bytes)
	if err != nil {
		b.Errorf("expected ca cert, got err: %s", err)
		b.FailNow()
	}

	validator := NewValidator(caCert)

	for i := 0; i < b.N; i++ {
		clientCert, err := DecodeFromDERBytes(clientCert4096Bytes)
		if err != nil {
			b.Errorf("expected client cert, got err: %s", err)
			b.FailNow()
		}

		validator.Validate(clientCert)
	}
}

func BenchmarkValidatorValidate4096KeySize(b *testing.B) {
	caCert, err := DecodeFromDERBytes(caCert4096Bytes)
	if err != nil {
		b.Errorf("expected ca cert, got err: %s", err)
		b.FailNow()
	}
	validator := NewValidator(caCert)

	clientCert, err := DecodeFromDERBytes(clientCert4096Bytes)
	if err != nil {
		b.Errorf("expected client cert, got err: %s", err)
		b.FailNow()
	}

	for i := 0; i < b.N; i++ {
		validator.Validate(clientCert)
	}
}
