package metadata

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestProductionMetadataTOCParsing(t *testing.T) {
	decoder, err := NewDecoder(WithIgnoreEntryParsingErrors())
	require.NoError(t, err)

	client := &http.Client{}

	res, err := client.Get(ProductionMDSURL)
	require.NoError(t, err)

	payload, err := decoder.Decode(res.Body)
	require.NoError(t, err)

	var metadata *Metadata

	metadata, err = decoder.Parse(payload)
	require.NoError(t, err)
	require.NotNil(t, metadata)
}

func TestConformanceMetadataTOCParsing(t *testing.T) {
	client := &http.Client{
		Timeout: time.Second * 30,
	}

	testCases := []struct {
		name string
		pass bool
	}{
		{
			"fido2_good",
			true,
		},
		{
			"fido2_badReports",
			false,
		},
		{
			"fido2_badSignature",
			false,
		},
		{
			"fido2_badCertificateChain",
			false,
		},
		{
			"fido2_intermediateCertificateRevoked",
			false,
		},
		{
			"fido2_subjectCertificateRevoked",
			false,
		},
	}

	endpoints, err := getEndpoints(client)
	require.NoError(t, err)

	decoder, err := NewDecoder(WithRootCertificate(ConformanceMDSRoot))

	require.NoError(t, err)

	metadata := make(map[uuid.UUID]EntryJSON)

	var (
		res  *http.Response
		blob *PayloadJSON
		me   *Error
	)

	for _, endpoint := range endpoints {
		res, err = client.Get(endpoint)
		require.NoError(t, err)

		if blob, err = decoder.Decode(res.Body); err != nil {
			if errors.As(err, &me) {
				t.Log(me.Details)
			}
		}

		if blob != nil {
			for _, entry := range blob.Entries {
				aaguid, _ := uuid.Parse(entry.AaGUID)
				metadata[aaguid] = entry
			}
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statement, err := getTestMetadata(tc.name, client)
			require.NoError(t, err)

			aaguid, _ := uuid.Parse(statement.AaGUID)
			if meta, ok := metadata[aaguid]; ok {
				pass := true

				for _, report := range meta.StatusReports {
					if IsUndesiredAuthenticatorStatus(report.Status) {
						pass = false
					}
				}

				assert.Equal(t, tc.pass, pass, "One or more status reports had an undesired status but this was not expected.")

				_, err := meta.Parse()
				assert.NoError(t, err, "Failed to parse metadata")
			} else {
				assert.False(t, tc.pass)
			}
		})
	}
}

const (
	exampleMetadataBLOB = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDWlRDQ0FndWdBd0lCQWdJQkFUQUtCZ2dxaGtqT1BRUURBakNCb3pFbk1DVUdBMVVFQXd3ZVJWaEJUVkJNUlNCTlJGTXpJRlJGVTFRZ1NVNVVSVkpOUlVSSlFWUkZNU0l3SUFZSktvWklodmNOQVFrQkZoTmxlR0Z0Y0d4bFFHVjRZVzF3YkdVdVkyOXRNUlF3RWdZRFZRUUtEQXRGZUdGdGNHeGxJRTlTUnpFUU1BNEdBMVVFQ3d3SFJYaGhiWEJzWlRFTE1Ba0dBMVVFQmhNQ1ZWTXhDekFKQmdOVkJBZ01BazFaTVJJd0VBWURWUVFIREFsWFlXdGxabWxsYkdRd0hoY05NakV3TkRFNU1URXpOVEEzV2hjTk16RXdOREUzTVRFek5UQTNXakNCcFRFcE1DY0dBMVVFQXd3Z1JWaEJUVkJNUlNCTlJGTXpJRk5KUjA1SlRrY2dRMFZTVkVsR1NVTkJWRVV4SWpBZ0Jna3Foa2lHOXcwQkNRRVdFMlY0WVcxd2JHVkFaWGhoYlhCc1pTNWpiMjB4RkRBU0JnTlZCQW9NQzBWNFlXMXdiR1VnVDFKSE1SQXdEZ1lEVlFRTERBZEZlR0Z0Y0d4bE1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUVDQXdDVFZreEVqQVFCZ05WQkFjTUNWZGhhMlZtYVdWc1pEQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJOUUpzNndUcWl4YytTK1ZEQWFqRmxQTmF0MTBLRVdKRTVqY1dPdm02cXBPOVNEQUFNWnZiNEhIcnZzK1A1WVJwSHJTbFVQZHZLK3VFUWJkV2czMVA5dWpMREFxTUFrR0ExVWRFd1FDTUFBd0hRWURWUjBPQkJZRUZMcXNhcGNYVjRab1ZIQW5ScFBad1FlN1l5MjBNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUM2N3phOEVJdXlSaUtnTkRYSVAxczFhTHIzanpIOVdWWGZIeDRiSit6Q3NnSWdHL3RWQnV0T0pVVSt2dm9ISW8vb3RBVUFjSDViTkhQM3VJemlEUytQVFVjPSIsIk1JSUVIekNDQWdlZ0F3SUJBZ0lCQWpBTkJna3Foa2lHOXcwQkFRc0ZBRENCbXpFZk1CMEdBMVVFQXd3V1JWaEJUVkJNUlNCTlJGTXpJRlJGVTFRZ1VrOVBWREVpTUNBR0NTcUdTSWIzRFFFSkFSWVRaWGhoYlhCc1pVQmxlR0Z0Y0d4bExtTnZiVEVVTUJJR0ExVUVDZ3dMUlhoaGJYQnNaU0JQVWtjeEVEQU9CZ05WQkFzTUIwVjRZVzF3YkdVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpOV1RFU01CQUdBMVVFQnd3SlYyRnJaV1pwWld4a01CNFhEVEl4TURReE9URXhNelV3TjFvWERUUTRNRGt3TkRFeE16VXdOMW93Z2FNeEp6QWxCZ05WQkFNTUhrVllRVTFRVEVVZ1RVUlRNeUJVUlZOVUlFbE9WRVZTVFVWRVNVRlVSVEVpTUNBR0NTcUdTSWIzRFFFSkFSWVRaWGhoYlhCc1pVQmxlR0Z0Y0d4bExtTnZiVEVVTUJJR0ExVUVDZ3dMUlhoaGJYQnNaU0JQVWtjeEVEQU9CZ05WQkFzTUIwVjRZVzF3YkdVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpOV1RFU01CQUdBMVVFQnd3SlYyRnJaV1pwWld4a01Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU5HdW1CYlluRlFuVGpQMVJTZmM3MGhzaGdiaUkxWnRwd1E1bjZ4UkxBL1dxMFBTQ2ZMbDVxUStyN2RsY0sxZDNyM3ZMYSt2bTZHNnZLSEdDUEVlVXpxTXZNQzB3REFZRFZSMFRCQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVOazZGNFJKbkdHVkZlKzAvY2Jad2ZyWmQ3WlV3RFFZSktvWklodmNOQVFFTEJRQURnZ0lCQUNucDFmbTBGS2xXbVV0VHBsTHVZZzdtcHM0eFAvQ091OGRuYjM4dTFuTURWdU9UNCtDWmFpTTlBR3ozMTNHRDIyaGpMR3JtUHVZbjg2d0dPS0kzSE9yRXBzR2RNbWZ5N3RUbUtYL2VNL2VTM0ZFRFhabkU4MlBuNW9GSXlCVC9mOHNHdVh5T3NGWnFXQnZWZEJJSURsZENwRDRteE1RWlpPWnRUcmx2M1d2QlFNQy9kc2ljT3hlM1FLWHZXSGk2UWIvUmh1YWlwM3JQbXdNZis0SnBuSk8rSk1QcUFhVTFjQUg4SFZzZnJMQU1vS3MxNDhqMitjdmJwYVdtc1Q1cklvSC9lelZyUGFHL01PaUlncTc5dy9lZnV2U2k1QVg4SitrRG9MU0VmM2Q1d09na0pZQXFVcWNSeFhURUV0S0l6RE02aHphQlFGaUFXdlRuOUlsVldnbnRRYW1TWHZIK3R4YVRGOWlFbEh4VWY1SU5ZRlZjaUNwenRTcnlkZUh2L09DTlJmNy9MVnJpY01TbG84UmgrTzN5UDlWKzJ1TmYzWDhzUUpOdHVmclFOYXFxMTh3aVhsaVRMdWZTbjAyL2crbWtoSVVpTktmVE9KcHZDaktlQ25DRmN4UVUyL1hUM0toM0c4Z0RKd3NPNkVWUmpNVUp0NEFZS3plL2hFVUN3RjU1SUYybTNqSElvQ3U4alZmajI0Q2VFWDVkbmZ2U3IrU1Z2TjVRQjB1WjA1TTRybXlaWHlxQm0wekszZlIraUUwL1pwSW51d0xDN1grVzgyelhsbk1rcGxJM1ErSnhkN2pmUTE1U1lORTJLNnJ2UklUMDF3MFA5WnF5REY3a25HS3BSbHA3T3F4ZDM3YkQvVlViV3BRN2dJQWZzSk5INUtCTG93SEpGRmpXIl19.eyJsZWdhbEhlYWRlciI6IlJldHJpZXZhbCBhbmQgdXNlIG9mIHRoaXMgQkxPQiBpbmRpY2F0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgYXBwcm9wcmlhdGUgYWdyZWVtZW50IGxvY2F0ZWQgYXQgaHR0cHM6Ly9maWRvYWxsaWFuY2Uub3JnL21ldGFkYXRhL21ldGFkYXRhLWxlZ2FsLXRlcm1zLyIsIm5vIjoxNSwibmV4dFVwZGF0ZSI6IjIwMjAtMDMtMzAiLCJlbnRyaWVzIjpbeyJhYWlkIjoiMTIzNCM1Njc4IiwibWV0YWRhdGFTdGF0ZW1lbnQiOnsibGVnYWxIZWFkZXIiOiJodHRwczovL2ZpZG9hbGxpYW5jZS5vcmcvbWV0YWRhdGEvbWV0YWRhdGEtc3RhdGVtZW50LWxlZ2FsLWhlYWRlci8iLCJkZXNjcmlwdGlvbiI6IkZJRE8gQWxsaWFuY2UgU2FtcGxlIFVBRiBBdXRoZW50aWNhdG9yIiwiYWFpZCI6IjEyMzQjNTY3OCIsImFsdGVybmF0aXZlRGVzY3JpcHRpb25zIjp7InJ1LVJVIjoi0J_RgNC40LzQtdGAIFVBRiDQsNGD0YLQtdC90YLQuNGE0LjQutCw0YLQvtGA0LAg0L7RgiBGSURPIEFsbGlhbmNlIiwiZnItRlIiOiJFeGVtcGxlIFVBRiBhdXRoZW50aWNhdG9yIGRlIEZJRE8gQWxsaWFuY2UifSwiYXV0aGVudGljYXRvclZlcnNpb24iOjIsInByb3RvY29sRmFtaWx5IjoidWFmIiwic2NoZW1hIjozLCJ1cHYiOlt7Im1ham9yIjoxLCJtaW5vciI6MH0seyJtYWpvciI6MSwibWlub3IiOjF9XSwiYXV0aGVudGljYXRpb25BbGdvcml0aG1zIjpbInNlY3AyNTZyMV9lY2RzYV9zaGEyNTZfcmF3Il0sInB1YmxpY0tleUFsZ0FuZEVuY29kaW5ncyI6WyJlY2NfeDk2Ml9yYXciXSwiYXR0ZXN0YXRpb25UeXBlcyI6WyJiYXNpY19mdWxsIl0sInVzZXJWZXJpZmljYXRpb25EZXRhaWxzIjpbW3sidXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6ImZpbmdlcnByaW50X2ludGVybmFsIiwiYmFEZXNjIjp7InNlbGZBdHRlc3RlZEZBUiI6MC4wMDAwMiwibWF4UmV0cmllcyI6NSwiYmxvY2tTbG93ZG93biI6MzAsIm1heFRlbXBsYXRlcyI6NX19XV0sImtleVByb3RlY3Rpb24iOlsiaGFyZHdhcmUiLCJ0ZWUiXSwiaXNLZXlSZXN0cmljdGVkIjp0cnVlLCJtYXRjaGVyUHJvdGVjdGlvbiI6WyJ0ZWUiXSwiY3J5cHRvU3RyZW5ndGgiOjEyOCwiYXR0YWNobWVudEhpbnQiOlsiaW50ZXJuYWwiXSwidGNEaXNwbGF5IjpbImFueSIsInRlZSJdLCJ0Y0Rpc3BsYXlDb250ZW50VHlwZSI6ImltYWdlL3BuZyIsInRjRGlzcGxheVBOR0NoYXJhY3RlcmlzdGljcyI6W3sid2lkdGgiOjMyMCwiaGVpZ2h0Ijo0ODAsImJpdERlcHRoIjoxNiwiY29sb3JUeXBlIjoyLCJjb21wcmVzc2lvbiI6MCwiZmlsdGVyIjowLCJpbnRlcmxhY2UiOjB9XSwiYXR0ZXN0YXRpb25Sb290Q2VydGlmaWNhdGVzIjpbIk1JSUNQVENDQWVPZ0F3SUJBZ0lKQU91ZXh2VTNPeTJ3TUFvR0NDcUdTTTQ5QkFNQ01Ic3hJREFlQmdOVkJBTU1GMU5oYlhCc1pTQkJkSFJsYzNSaGRHbHZiaUJTYjI5ME1SWXdGQVlEVlFRS0RBMUdTVVJQSUVGc2JHbGhibU5sTVJFd0R3WURWUVFMREFoVlFVWWdWRmRITERFU01CQUdBMVVFQnd3SlVHRnNieUJCYkhSdk1Rc3dDUVlEVlFRSURBSkRRVEVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TmpFNE1UTXpNek15V2hjTk5ERXhNVEF6TVRNek16TXlXakI3TVNBd0hnWURWUVFEREJkVFlXMXdiR1VnUVhSMFpYTjBZWFJwYjI0Z1VtOXZkREVXTUJRR0ExVUVDZ3dOUmtsRVR5QkJiR3hwWVc1alpURVJNQThHQTFVRUN3d0lWVUZHSUZSWFJ5d3hFakFRQmdOVkJBY01DVkJoYkc4Z1FXeDBiekVMTUFrR0ExVUVDQXdDUTBFeEN6QUpCZ05WQkFZVEFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVIOGh2MkQwSFhhNTkvQm1wUTdSWmVoTC9GTUd6RmQxUUJnOXZBVXBPWjNham51UTk0UFI3YU16SDMzblVTQnI4ZkhZRHJxT0JiNThweEdxSEpSeVgvNk5RTUU0d0hRWURWUjBPQkJZRUZQb0hBM0NMaHhGYkMwSXQ3ekU0dzhoazVFSi9NQjhHQTFVZEl3UVlNQmFBRlBvSEEzQ0xoeEZiQzBJdDd6RTR3OGhrNUVKL01Bd0dBMVVkRXdRRk1BTUJBZjh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUowNlFTWHQ5aWhJYkVLWUtJanNQa3JpVmRMSWd0ZnNiRFN1N0VySmZ6cjRBaUJxb1lDWmYwK3pJNTVhUWVBSGpJekE5WG02M3JydUF4Qlo5cHM5ejJYTmxRPT0iXSwiaWNvbiI6ImRhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpVkJPUncwS0dnb0FBQUFOU1VoRVVnQUFBRThBQUFBdkNBWUFBQUNpd0pmY0FBQUFBWE5TUjBJQXJzNGM2UUFBQUFSblFVMUJBQUN4and2OFlRVUFBQUFKY0VoWmN3QUFEc01BQUE3REFjZHZxR1FBQUFhaFNVUkJWR2hEN1pyNWJ4UmxHTWY5S3pUQjhBTS9ZRWhFMlc3cFFaY1dLS0JjbFNwSEFUbEVMQVJFN2tORUNDQTNGa1dLMENLS1NDRklzS0JjZ1ZDRFdHTkVTZEFZaWR3Z2dnSkJpUmlNaEZjLzR3eTg4ODR6dTlOZGxuR1RmWkpQMm4zbk8rKzg4OTMzZnZlQkJ4K1BxQ3pKa1RVdkJiTG1wVURXdkJUSW1wY0NTWnZYTENkWDlSMDVTazE5YmI1YXRmNTk5ZkcrL2VyQTU0MXE0N2FQMUxMVmE5U0l5Vk5VaThJaThkNWtHVHNpMzBORnY3YWk5bjdRWlBNd2JkeXMyZXJVMlhNcVVkeTgrWmNhTm1HaW1FOHlYTjNSVWQzYTE4bkYwZlVsb3ZaKzBDVHpXcGQyVmorZU9tMWJFeXk2RHg0aTVwVU1HV3ZlbzUwNnEyMjdkdHVXQkl1ZmZyNm9XcFYwRlBOTGhvdzE3NTFObTIxTHZQSDNyVnRXamZ6NjZMZnFsOHRYN0ZSbDlZRlNYc21Tc2ViOWNlT0diWWs3TU5VY0dQZzhac2JNZTlyZlFVYWFWL0pNWDlzcWR6RENTdnAwa1pIbVRaZzl4N2JMSGNNblRoYjE2ZUorbVZmUXE4eWFVWlFORzY0aVhaKzAva3E2dU9aRk8wUXRhdGRXS2ZYblJROTlCajkxUjVPSUZuazU0ak4wbWtVaXFsTzNYRFcrTWwrOThtS0I2dFc3cldwWmNQYyswemc0dExyWWxVYzg2RTZlR0RqSU11YlZwY3VzZWFyZmdJWUdSazZicmhaVnIvSmNIem9vTDc1NTBqZWRMRXhvcFdjQXBpMlpVcWh1N0pMdnJWc1FVODF6a3pPUGVlbU1SWXZWdVFzWDdQYmlEUVk1SnZab25mdEsrMVZZOEg5dXR4NTMwaDBvYitqbVJZcWo2b3VhWXZFZW5XL1dsWWpwOGN3Yk1tNjgydFB3cVcxUjR0ai8yU0gxM0lSSllsNG1vWnZYcGlTcURyN2RYdFFIeGEvUEszLytCV3NLMWRUZ0h1NlY4dFFKM2J3Rmt3cEZyVU9RNTBzMXIzbGV2bTh6WmNxMTcrQkJhdzdLOGxFSzVxemtZZWFyazlBOHA3UDNHekRLK25kM0RRb3crNlVDOFNWTjgyaXV2MzhpbTdOdGFYdFYxQ1ZxNlJndzRwa3NtYmRpM2J1MkRlN1lmYUJCeGNxZnZxUHJVakZRTlRRMjJsZmRVVlZUNjhyVEpLRjVEblNtVWpnZHFnNG1TUzlwbXNmREpSM0c2VG9IMGlXOWFWN0xXTEhZWEtsbFREdDBMVEF0a1lJYWFtcDFRalZ2Kyt1eUdVeFZkSjBETlZYU20rYjFxUnhwbDg0ZGRmWDFMcDFPL2Q2OXRzb2QwdnM1aEdyZTl4dThvK2ZwTFIxY0doTlRENlo1N0M5S01XWGVmSmRPWjk0YmI5b3FkMVJPblM3cUlUVHpIaW1NcWl2Yk8zZzBEZFZ5azNXUUJoQnp0SzM1WUtOZE9uYzhPM2FjUzZmRFpGZ0thWExzRUpwNXJkcmxpQnFwODljSmNzL203VHZzMHJrakdmTjRiMGtQb1puM1VKdUlPcm5aMjJ5UDFmbXZVeCtPNWdTcWViVjFtK3pTdVlOVmhxN1RXYkRpTFZ2bGpwbExsb3A2Q0xYUCsycXR2R0xJTC8xdmltSVNkTUJnelNvRlp5dTZUcWQranp4Z3NQYVY5QkNxZWUvTmpZazZ2NmxLOWN3aVVjL1NUdGYxSERwTTNiNTkyeTdoM1RoeDVveks2OUhMcFlXdUF3YXFTNWN2MjZxN2NlYjhlZlZZYVJlUDNpRlU4emoxa25Td1pYSE1tbkNqWTBPZ2FsbzdVUWZTQ00zcVFRcjJIL1hGUDdzc1h4NDVZbDkxQnllQ2VwNG1vWm9IKzFmRzN4RDR0VDd4OGt3eWo4bndiOWV2MjZWMEI2ZCs3SDR6S3Z1ZEFINTM3RmpxeXpPSGRKbkhFdXptWHEvV2p4T2J2Tk1idjduaHl3c1gyYVZzV3RDOCs0OGFMZWFwRTdwNXdLWmkwQTJBUVJWNW52UjRFK3VKYytiNjFrQXBxSW54QmdtZC80VjVRUC9tdDE4SERDN3NSSGZ0bWV1NWxtaFYwcm4vQUxYMjMyYnFkNEJGbkR4N1ZpMWNXUzJ1ZmYwSWJCNDdxZXh4bVVqOVF1dFlqdXBkM3RZRDZhYldCQk1yaCthcE5iT0tyTkYxK3VnQ2E0cmlYR2Z3TVBQdFZpYXZoVTNZTU9BQW51VWIvUjA3TDB5T1NlT2FkRTg4QXBzWEZHZmYzMHluaGxKZ001MUNVNnZOOUV6Z25wdkhCRlV5aVZyYWVQaXdKNTNERjVaVFpub21FTmc4NWtOVWQyb0ppMldwcjRPbW1rZk40eDR6SGZpVkZjOER2OE56dWhOcU9pZGlsR3ZBNkRHdWVad083OEFBUW42Y2lFazYrcnc1VmN2anZxTkRZUE9vSVV3YUtTaHJ4QXVYTGxrSDRhWXVHZk1ZRGMxMFdGNVRhMzFoUEpPZmNVaHJVL0psSU5pNmM2ZWxSWWRCcG82KytZZmp4NjFsR05mUm00TUQ1ckoxajNGb0dIbmpEU0JOYXJZVWdNTHlNc3pLcGI3dFhwb0hmUHM4aDNXcDFMek5mTms1NFh4QzF3REdVbVl6WFllZmg2ei9jS3RWbTRFQnhhOVZRR0R6WXIzTHJVTVJqSEVLa2s3emFGS1lRQTJoR1FVMXorODVORldwWERya3ozdngxMEdxeFE2QnplTmJvQms1bjhrNG5lYlJoK2sxaFdmeFRGMEQxRXlXVXM1bnYrZGdRcUtheHp1Q2RFMGlzSGwwMk5ROGFoMG1YcjEyTGEzbTBmOXdpazkrd0xOVE1ZLzg2TVBvOHlpMzFPZnhtVDZQV29xRzkrRFp1a1luYTU2bVNadDVXV1N5NXFWQTFyd1V5SnFYQWxuemtpYWkvZ0hTRDdSa1R5aWhvZ0FBQUFCSlJVNUVya0pnZ2c9PSJ9LCJzdGF0dXNSZXBvcnRzIjpbeyJzdGF0dXMiOiJGSURPX0NFUlRJRklFRCIsImVmZmVjdGl2ZURhdGUiOiIyMDE0LTAxLTA0In1dLCJ0aW1lT2ZMYXN0U3RhdHVzQ2hhbmdlIjoiMjAxNC0wMS0wNCJ9LHsiYWFndWlkIjoiMDEzMmQxMTAtYmY0ZS00MjA4LWE0MDMtYWI0ZjVmMTJlZmU1IiwibWV0YWRhdGFTdGF0ZW1lbnQiOnsibGVnYWxIZWFkZXIiOiJodHRwczovL2ZpZG9hbGxpYW5jZS5vcmcvbWV0YWRhdGEvbWV0YWRhdGEtc3RhdGVtZW50LWxlZ2FsLWhlYWRlci8iLCJkZXNjcmlwdGlvbiI6IkZJRE8gQWxsaWFuY2UgU2FtcGxlIEZJRE8yIEF1dGhlbnRpY2F0b3IiLCJhYWd1aWQiOiIwMTMyZDExMC1iZjRlLTQyMDgtYTQwMy1hYjRmNWYxMmVmZTUiLCJhbHRlcm5hdGl2ZURlc2NyaXB0aW9ucyI6eyJydS1SVSI6ItCf0YDQuNC80LXRgCBGSURPMiDQsNGD0YLQtdC90YLQuNGE0LjQutCw0YLQvtGA0LAg0L7RgiBGSURPIEFsbGlhbmNlIiwiZnItRlIiOiJFeGVtcGxlIEZJRE8yIGF1dGhlbnRpY2F0b3IgZGUgRklETyBBbGxpYW5jZSIsInpoLUNOIjoi5L6G6IeqRklETyBBbGxpYW5jZeeahOekuuS-i0ZJRE8y6Lqr5Lu96amX6K2J5ZmoIn0sInByb3RvY29sRmFtaWx5IjoiZmlkbzIiLCJzY2hlbWEiOjMsImF1dGhlbnRpY2F0b3JWZXJzaW9uIjo1LCJ1cHYiOlt7Im1ham9yIjoxLCJtaW5vciI6MH1dLCJhdXRoZW50aWNhdGlvbkFsZ29yaXRobXMiOlsic2VjcDI1NnIxX2VjZHNhX3NoYTI1Nl9yYXciLCJyc2Fzc2FfcGtjc3YxNV9zaGEyNTZfcmF3Il0sInB1YmxpY0tleUFsZ0FuZEVuY29kaW5ncyI6WyJjb3NlIl0sImF0dGVzdGF0aW9uVHlwZXMiOlsiYmFzaWNfZnVsbCJdLCJ1c2VyVmVyaWZpY2F0aW9uRGV0YWlscyI6W1t7InVzZXJWZXJpZmljYXRpb25NZXRob2QiOiJub25lIn1dLFt7InVzZXJWZXJpZmljYXRpb25NZXRob2QiOiJwcmVzZW5jZV9pbnRlcm5hbCJ9XSxbeyJ1c2VyVmVyaWZpY2F0aW9uTWV0aG9kIjoicGFzc2NvZGVfZXh0ZXJuYWwiLCJjYURlc2MiOnsiYmFzZSI6MTAsIm1pbkxlbmd0aCI6NH19XSxbeyJ1c2VyVmVyaWZpY2F0aW9uTWV0aG9kIjoicGFzc2NvZGVfZXh0ZXJuYWwiLCJjYURlc2MiOnsiYmFzZSI6MTAsIm1pbkxlbmd0aCI6NH19LHsidXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6InByZXNlbmNlX2ludGVybmFsIn1dXSwia2V5UHJvdGVjdGlvbiI6WyJoYXJkd2FyZSIsInNlY3VyZV9lbGVtZW50Il0sIm1hdGNoZXJQcm90ZWN0aW9uIjpbIm9uX2NoaXAiXSwiY3J5cHRvU3RyZW5ndGgiOjEyOCwiYXR0YWNobWVudEhpbnQiOlsiZXh0ZXJuYWwiLCJ3aXJlZCIsIndpcmVsZXNzIiwibmZjIl0sInRjRGlzcGxheSI6W10sImF0dGVzdGF0aW9uUm9vdENlcnRpZmljYXRlcyI6WyJNSUlDUFRDQ0FlT2dBd0lCQWdJSkFPdWV4dlUzT3kyd01Bb0dDQ3FHU000OUJBTUNNSHN4SURBZUJnTlZCQU1NRjFOaGJYQnNaU0JCZEhSbGMzUmhkR2x2YmlCU2IyOTBNUll3RkFZRFZRUUtEQTFHU1VSUElFRnNiR2xoYm1ObE1SRXdEd1lEVlFRTERBaFZRVVlnVkZkSExERVNNQkFHQTFVRUJ3d0pVR0ZzYnlCQmJIUnZNUXN3Q1FZRFZRUUlEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTXdIaGNOTVRRd05qRTRNVE16TXpNeVdoY05OREV4TVRBek1UTXpNek15V2pCN01TQXdIZ1lEVlFRRERCZFRZVzF3YkdVZ1FYUjBaWE4wWVhScGIyNGdVbTl2ZERFV01CUUdBMVVFQ2d3TlJrbEVUeUJCYkd4cFlXNWpaVEVSTUE4R0ExVUVDd3dJVlVGR0lGUlhSeXd4RWpBUUJnTlZCQWNNQ1ZCaGJHOGdRV3gwYnpFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKQmdOVkJBWVRBbFZUTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSDhodjJEMEhYYTU5L0JtcFE3UlplaEwvRk1HekZkMVFCZzl2QVVwT1ozYWpudVE5NFBSN2FNekgzM25VU0JyOGZIWURycU9CYjU4cHhHcUhKUnlYLzZOUU1FNHdIUVlEVlIwT0JCWUVGUG9IQTNDTGh4RmJDMEl0N3pFNHc4aGs1RUovTUI4R0ExVWRJd1FZTUJhQUZQb0hBM0NMaHhGYkMwSXQ3ekU0dzhoazVFSi9NQXdHQTFVZEV3UUZNQU1CQWY4d0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFKMDZRU1h0OWloSWJFS1lLSWpzUGtyaVZkTElndGZzYkRTdTdFckpmenI0QWlCcW9ZQ1pmMCt6STU1YVFlQUhqSXpBOVhtNjNycnVBeEJaOXBzOXoyWE5sUT09Il0sImljb24iOiJkYXRhOmltYWdlL3BuZztiYXNlNjQsaVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQUU4QUFBQXZDQVlBQUFDaXdKZmNBQUFBQVhOU1IwSUFyczRjNlFBQUFBUm5RVTFCQUFDeGp3djhZUVVBQUFBSmNFaFpjd0FBRHNNQUFBN0RBY2R2cUdRQUFBYWhTVVJCVkdoRDdacjVieFJsR01mOUt6VEI4QU0vWUVoRTJXN3BRWmNXS0tCY2xTcEhBVGxFTEFSRTdrTkVDQ0EzRmtXSzBDS0tTQ0ZJc0tCY2dWQ0RXR05FU2RBWWlkd2dnZ0pCaVJpTWhGYy80d3k4ODg0enU5TmRsbkdUZlpKUDJuM25PKys4ODkzM2Z2ZUJCeCtQcUN6SmtUVXZCYkxtcFVEV3ZCVEltcGNDU1p2WExDZFg5UjA1U2sxOWJiNWF0ZjU5OWZHKy9lckE1NDFxNDdhUDFMTFZhOVNJeVZOVWk4SWk4ZDVrR1RzaTMwTkZ2N2FpOW43UVpQTXdiZHlzMmVyVTJYTXFVZHk4K1pjYU5tR2ltRTh5WE4zUlVkM2ExOG5GMGZVbG92WiswQ1R6V3BkMlZqK2VPbTFiRXl5NkR4NGk1cFVNR1d2ZW81MDZxMjI3ZHR1V0JJdWZmcjZvV3BWMEZQTkxob3cxNzUxTm0yMUx2UEgzclZ0V2pmejY2TGZxbDh0WDdGUmw5WUZTWHNtU3NlYjljZU9HYllrN01OVWNHUGc4WnNiTWU5cmZRVWFhVi9KTVg5c3FkekRDU3ZwMGtaSG1UWmc5eDdiTEhjTW5UaGIxNmVKK21WZlFxOHlhVVpRTkc2NGlYWiswL2txNnVPWkZPMFF0YXRkV0tmWG5SUTk5Qmo5MVI1T0lGbms1NGpOMG1rVWlxbE8zWERXK01sKzk4bUtCNnRXN3JXcFpjUGMrMHpnNHRMcllsVWM4NkU2ZUdEaklNdWJWcGN1c2VhcmZnSVlHUms2YnJoWlZyL0pjSHpvb0w3NTUwamVkTEV4b3BXY0FwaTJaVXFodTdKTHZyVnNRVTgxemt6T1BlZW1NUll2VnVRc1g3UGJpRFFZNUp2Wm9uZnRLKzFWWThIOXV0eDUzMGgwb2Iram1SWXFqNm91YVl2RWVuVy9XbFlqcDhjd2JNbTY4MnRQd3FXMVI0dGovMlNIMTNJUkpZbDRtb1p2WHBpU3FEcjdkWHRRSHhhL1BLMy8rQldzSzFkVGdIdTZWOHRRSjNid0Zrd3BGclVPUTUwczFyM2xldm04elpjcTE3K0JCYXc3SzhsRUs1cXprWWVhcms5QThwN1AzR3pESytuZDNEUW93KzZVQzhTVk44Mml1djM4aW03TnRhWHRWMUNWcTZSZ3c0cGtzbWJkaTNidTJEZTdZZmFCQnhjcWZ2cVByVWpGUU5UUTIybGZkVVZWVDY4clRKS0Y1RG5TbVVqZ2RxZzRtU1M5cG1zZkRKUjNHNlRvSDBpVzlhVjdMV0xIWVhLbGxURHQwTFRBdGtZSWFhbXAxUWpWdisrdXlHVXhWZEowRE5WWFNtK2IxcVJ4cGw4NGRkZlgxTHAxTy9kNjl0c29kMHZzNWhHcmU5eHU4bytmcExSMWNHaE5URDZaNTdDOUtNV1hlZkpkT1o5NGJiOW9xZDFST25TN3FJVFR6SGltTXFpdmJPM2cwRGRWeWszV1FCaEJ6dEszNVlLTmRPbmM4TzNhY1M2ZkRaRmdLYVhMc0VKcDVyZHJsaUJxcDg5Y0pjcy9tN1R2czBya2pHZk40YjBrUG9abjNVSnVJT3JuWjIyeVAxZm12VXgrTzVnU3FlYlYxbSt6U3VZTlZocTdUV2JEaUxWdmxqcGxMbG9wNkNMWFArMnF0dkdMSUwvMXZpbUlTZE1CZ3pTb0ZaeXU2VHFkK2p6eGdzUGFWOUJDcWVlL05qWWs2djZsSzljd2lVYy9TVHRmMUhEcE0zYjU5Mnk3aDNUaHg1b3pLNjlITHBZV3VBd2FxUzVjdjI2cTdjZWI4ZWZWWWFSZVAzaUZVOHpqMWtuU3daWEhNbW5DalkwT2dhbG83VVFmU0NNM3FRUXIySC9YRlA3c3NYeDQ1WWw5MUJ5ZUNlcDRtb1pvSCsxZkczeEQ0dFQ3eDhrd3lqOG53YjlldjI2VjBCNmQrN0g0ekt2dWRBSDUzN0ZqcXl6T0hkSm5IRXV6bVhxL1dqeE9idk5NYnY3bmh5d3NYMmFWc1d0QzgrNDhhTGVhcEU3cDV3S1ppMEEyQVFSVjVudlI0RSt1SmMrYjYxa0FwcUlueEJnbWQvNFY1UVAvbXQxOEhEQzdzUkhmdG1ldTVsbWhWMHJuL0FMWDIzMmJxZDRCRm5EeDdWaTFjV1MydWZmMEliQjQ3cWV4eG1VajlRdXRZanVwZDN0WUQ2YWJXQkJNcmgrYXBOYk9Lck5GMSt1Z0NhNHJpWEdmd01QUHRWaWF2aFUzWU1PQUFudVViL1IwN0wweU9TZU9hZEU4OEFwc1hGR2ZmMzB5bmhsSmdNNTFDVTZ2TjlFemducHZIQkZVeWlWcmFlUGl3SjUzREY1WlRabm9tRU5nODVrTlVkMm9KaTJXcHI0T21ta2ZONHg0ekhmaVZGYzhEdjhOenVoTnFPaWRpbEd2QTZER3VlWndPNzhBQVFuNmNpRWs2K3J3NVZjdmp2cU5EWVBPb0lVd2FLU2hyeEF1WExsa0g0YVl1R2ZNWURjMTBXRjVUYTMxaFBKT2ZjVWhyVS9KbElOaTZjNmVsUllkQnBvNisrWWZqeDYxbEdOZlJtNE1ENXJKMWozRm9HSG5qRFNCTmFyWVVnTUx5TXN6S3BiN3RYcG9IZlBzOGgzV3AxTHpOZk5rNTRYeEMxd0RHVW1ZelhZZWZoNnovY0t0Vm00RUJ4YTlWUUdEellyM0xyVU1SakhFS2trN3phRktZUUEyaEdRVTF6Kzg1TkZXcFhEcmt6M3Z4MTBHcXhRNkJ6ZU5ib0JrNW44azRuZWJSaCtrMWhXZnhURjBEMUV5V1VzNW52K2RnUXFLYXh6dUNkRTBpc0hsMDJOUThhaDBtWHIxMkxhM20wZjl3aWs5K3dMTlRNWS84Nk1Qbzh5aTMxT2Z4bVQ2UFdvcUc5K0RadWtZbmE1Nm1TWnQ1V1dTeTVxVkExcndVeUpxWEFsbnpraWFpL2dIU0Q3UmtUeWlob2dBQUFBQkpSVTVFcmtKZ2dnPT0iLCJzdXBwb3J0ZWRFeHRlbnNpb25zIjpbeyJpZCI6ImhtYWMtc2VjcmV0IiwiZmFpbF9pZl91bmtub3duIjpmYWxzZX0seyJpZCI6ImNyZWRQcm90ZWN0IiwiZmFpbF9pZl91bmtub3duIjpmYWxzZX1dLCJhdXRoZW50aWNhdG9yR2V0SW5mbyI6eyJ2ZXJzaW9ucyI6WyJVMkZfVjIiLCJGSURPXzJfMCJdLCJleHRlbnNpb25zIjpbImNyZWRQcm90ZWN0IiwiaG1hYy1zZWNyZXQiXSwiYWFndWlkIjoiMDEzMmQxMTBiZjRlNDIwOGE0MDNhYjRmNWYxMmVmZTUiLCJvcHRpb25zIjp7InBsYXQiOmZhbHNlLCJyayI6dHJ1ZSwiY2xpZW50UGluIjp0cnVlLCJ1cCI6dHJ1ZSwidXYiOnRydWUsInV2VG9rZW4iOmZhbHNlLCJjb25maWciOmZhbHNlfSwibWF4TXNnU2l6ZSI6MTIwMCwicGluVXZBdXRoUHJvdG9jb2xzIjpbMV0sIm1heENyZWRlbnRpYWxDb3VudEluTGlzdCI6MTYsIm1heENyZWRlbnRpYWxJZExlbmd0aCI6MTI4LCJ0cmFuc3BvcnRzIjpbInVzYiIsIm5mYyJdLCJhbGdvcml0aG1zIjpbeyJ0eXBlIjoicHVibGljLWtleSIsImFsZyI6LTd9LHsidHlwZSI6InB1YmxpYy1rZXkiLCJhbGciOi0yNTd9XSwibWF4QXV0aGVudGljYXRvckNvbmZpZ0xlbmd0aCI6MTAyNCwiZGVmYXVsdENyZWRQcm90ZWN0IjoyLCJmaXJtd2FyZVZlcnNpb24iOjV9fSwic3RhdHVzUmVwb3J0cyI6W3sic3RhdHVzIjoiRklET19DRVJUSUZJRUQiLCJlZmZlY3RpdmVEYXRlIjoiMjAxOS0wMS0wNCJ9LHsic3RhdHVzIjoiRklET19DRVJUSUZJRURfTDEiLCJlZmZlY3RpdmVEYXRlIjoiMjAyMC0xMS0xOSIsImNlcnRpZmljYXRpb25EZXNjcmlwdG9yIjoiRklETyBBbGxpYW5jZSBTYW1wbGUgRklETzIgQXV0aGVudGljYXRvciIsImNlcnRpZmljYXRlTnVtYmVyIjoiRklETzIxMDAwMjAxNTEyMjEwMDEiLCJjZXJ0aWZpY2F0aW9uUG9saWN5VmVyc2lvbiI6IjEuMC4xIiwiY2VydGlmaWNhdGlvblJlcXVpcmVtZW50c1ZlcnNpb24iOiIxLjAuMSJ9XSwidGltZU9mTGFzdFN0YXR1c0NoYW5nZSI6IjIwMTktMDEtMDQifV19._tmf5mXw0RPlK3RgYlMqmtog9wsHjY-BjHGSZrrDhTrFwHj-g5CiG-AXgNnHLUHEm2_2DOJonEte7PbJEkeLeA"
)

func TestExampleMetadataTOCParsing(t *testing.T) {
	exampleMetadataBLOBBytes := bytes.NewBufferString(exampleMetadataBLOB)

	decoder, err := NewDecoder(WithIgnoreEntryParsingErrors(), WithRootCertificate(ExampleMDSRoot))

	require.NoError(t, err)

	payload, err := decoder.DecodeBytes(exampleMetadataBLOBBytes.Bytes())
	require.NoError(t, err)

	_, err = decoder.Parse(payload)

	require.NoError(t, err)
}

func TestIsUndesiredAuthenticatorStatus(t *testing.T) {
	tests := []struct {
		status AuthenticatorStatus
		fail   bool
	}{
		{
			NotFidoCertified,
			false,
		},
		{
			FidoCertified,
			false,
		},
		{
			UserVerificationBypass,
			true,
		},
		{
			AttestationKeyCompromise,
			true,
		},
		{
			UserKeyRemoteCompromise,
			true,
		},
		{
			UserKeyPhysicalCompromise,
			true,
		},
		{
			UpdateAvailable,
			false,
		},
		{
			Revoked,
			true,
		},
		{
			SelfAssertionSubmitted,
			false,
		},
		{
			FidoCertifiedL1,
			false,
		},
		{
			FidoCertifiedL1plus,
			false,
		},
		{
			FidoCertifiedL2,
			false,
		},
		{
			FidoCertifiedL2plus,
			false,
		},
		{
			FidoCertifiedL3,
			false,
		},
		{
			FidoCertifiedL3plus,
			false,
		},
		{
			FIPS140CertifiedL1,
			false,
		},
		{
			FIPS140CertifiedL2,
			false,
		},
		{
			FIPS140CertifiedL3,
			false,
		},
		{
			FIPS140CertifiedL4,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if tt.fail != IsUndesiredAuthenticatorStatus(tt.status) {
				t.Fail()
			}
		})
	}
}

func TestAlgKeyMatch(t *testing.T) {
	tests := []struct {
		name string
		alg  algKeyCose
		algs []AuthenticationAlgorithm
		fail bool
	}{
		{
			"Positive match RS256",
			algKeyCose{KeyType: webauthncose.RSAKey, Algorithm: webauthncose.AlgRS256},
			[]AuthenticationAlgorithm{ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW},
			true,
		},
		{
			"Positive match ES256",
			algKeyCose{KeyType: webauthncose.EllipticKey, Algorithm: webauthncose.AlgES256, Curve: webauthncose.P256},
			[]AuthenticationAlgorithm{ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, ALG_SIGN_SECP256R1_ECDSA_SHA256_DER},
			true,
		},
		{
			"Positive match Ed25519",
			algKeyCose{KeyType: webauthncose.OctetKey, Algorithm: webauthncose.AlgEdDSA, Curve: webauthncose.Ed25519},
			[]AuthenticationAlgorithm{ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, ALG_SIGN_ED25519_EDDSA_SHA512_RAW},
			true,
		},
		{
			"Negative match Ed25519, array missing Ed25519",
			algKeyCose{KeyType: webauthncose.OctetKey, Algorithm: webauthncose.AlgEdDSA, Curve: webauthncose.Ed25519},
			[]AuthenticationAlgorithm{ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW, ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, ALG_SIGN_SECP256R1_ECDSA_SHA256_DER},
			false,
		},
		{
			"Negative match RS256, array missing RS256",
			algKeyCose{KeyType: webauthncose.RSAKey, Algorithm: webauthncose.AlgRS256},
			[]AuthenticationAlgorithm{ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, ALG_SIGN_SECP256R1_ECDSA_SHA256_DER, ALG_SIGN_ED25519_EDDSA_SHA512_RAW},
			false,
		},
		{
			"Negative match ES256, array missing ES256",
			algKeyCose{KeyType: webauthncose.EllipticKey, Algorithm: webauthncose.AlgES256},
			[]AuthenticationAlgorithm{ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW, ALG_SIGN_ED25519_EDDSA_SHA512_RAW},
			false,
		},
		{
			"Negative match, curve/alg mismatch",
			algKeyCose{KeyType: webauthncose.EllipticKey, Algorithm: webauthncose.AlgES256, Curve: webauthncose.P384},
			[]AuthenticationAlgorithm{ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, ALG_SIGN_SECP256R1_ECDSA_SHA256_DER, ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW},
			false,
		},
		{
			"Negative match, kty/crv mismatch",
			algKeyCose{KeyType: webauthncose.RSAKey, Algorithm: webauthncose.AlgRS256, Curve: webauthncose.P256},
			[]AuthenticationAlgorithm{ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, ALG_SIGN_SECP256R1_ECDSA_SHA256_DER, ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fail != AlgKeyMatch(tt.alg, tt.algs) {
				t.Fail()
			}
		})
	}
}

func getEndpoints(c *http.Client) ([]string, error) {
	jsonReq, err := json.Marshal(MDSGetEndpointsRequest{Endpoint: "https://webauthn.io"})
	if err != nil {
		return nil, err
	}

	req, err := c.Post("https://mds3.fido.tools/getEndpoints", "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, err
	}

	defer req.Body.Close()
	body, _ := io.ReadAll(req.Body)

	var resp MDSGetEndpointsResponse

	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return resp.Result, err
}

func getTestMetadata(s string, c *http.Client) (StatementJSON, error) {
	var statement StatementJSON

	// MDSGetEndpointsRequest is the request sent to the conformance metadata getEndpoints endpoint.
	type MDSGetTestMetadata struct {
		// The URL of the local server endpoint, e.g. https://webauthn.io/
		Endpoint string `json:"endpoint"`
		TestCase string `json:"testcase"`
	}

	jsonReq, err := json.Marshal(MDSGetTestMetadata{Endpoint: "https://webauthn.io", TestCase: s})
	if err != nil {
		return statement, err
	}

	req, err := c.Post("https://mds3.fido.tools/getTestMetadata", "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return statement, err
	}

	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return statement, err
	}

	type ConformanceResponse struct {
		Status string        `json:"status"`
		Result StatementJSON `json:"result"`
	}

	var resp ConformanceResponse

	if err = json.Unmarshal(body, &resp); err != nil {
		return statement, err
	}

	statement = resp.Result

	return statement, err
}
