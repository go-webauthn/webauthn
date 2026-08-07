package protocol

import (
	"strings"
)

// The values below are Table 2 (TPM Capabilities Vendor ID) of the TCG TPM Vendor ID Registry Family 1.2 and 2.0,
// Version 1.08, July 20, 2026. This is the table which applies as the TPMManufacturer SAN value carries the
// TPM_PT_MANUFACTURER property, not the 16-bit hardware interface VenID of Table 1.
//
// Values in Table 1 with no Table 2 equivalent (i.e. Solidigm), and the simulator and testing values of Table 3, are
// intentionally excluded as they must not appear in a production attestation.
//
// See https://trustedcomputinggroup.org/resource/vendor-id-registry/ for registry contents.
var (
	tpmManufacturers = []tpmManufacturer{
		{"414D4400", "AMD", "AMD"},
		{"414E5400", "Ant Group", "ANT"},
		{"41524D00", "Arm", "ARM"},
		{"41544D4C", "Atmel", "ATML"},
		{"4252434D", "Broadcom", "BRCM"},
		{"4353434F", "Cisco", "CSCO"},
		{"464C5953", "Flyslice Technologies", "FLYS"},
		{"524F4343", "Fuzhou Rockchip", "ROCC"},
		{"474F4F47", "Google", "GOOG"},
		{"48504900", "HPI", "HPI"},
		{"48504500", "HPE", "HPE"},
		{"48495349", "Huawei", "HISI"},
		{"49424D00", "IBM", "IBM"},
		{"49465800", "Infineon", "IFX"},
		{"494E5443", "Intel", "INTC"},
		{"4C454E00", "Lenovo", "LEN"},
		{"4D534654", "Microsoft", "MSFT"},
		{"4E534D20", "National Semiconductor", "NSM"},
		{"4E545A00", "Nationz", "NTZ"},
		{"4E534700", "NSING", "NSG"},
		{"4E544300", "Nuvoton Technology", "NTC"},
		{"51434F4D", "Qualcomm", "QCOM"},
		{"534D534E", "Samsung", "SMSN"},
		{"53454345", "SecEdge", "SECE"},
		{"534E5300", "Sinosun", "SNS"},
		{"534D5343", "SMSC", "SMSC"},
		{"53544D20", "STMicroelectronics", "STM"},
		{"54584E00", "Texas Instruments", "TXN"},
		{"57454300", "Winbond", "WEC"},
		{"5345414C", "Wisekey", "SEAL"},

		// The following value is not assigned by the TCG, it's used by the FIDO Alliance conformance tooling.
		{"FFFFF1D0", "FIDO Alliance Conformance Testing", "FIDO"},
	}
)

// isValidTPMManufacturer determines if the given TPM manufacturer id is registered. The comparison is deliberately
// case-insensitive as the id is the hexadecimal representation of a four byte value rendered as a string by the
// authenticator, and the case of the hexadecimal digits is not fixed by any specification. The TCG registry itself
// renders IBM as '0x49 0x42 0x4d 0x00' with a lowercase digit.
func isValidTPMManufacturer(id string) bool {
	for _, m := range tpmManufacturers {
		if strings.EqualFold(m.id, id) {
			return true
		}
	}

	return false
}
