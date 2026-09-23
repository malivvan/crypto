// Package ecc implements a generic interface for ECDH and EdDSA.
package ecc

import (
	"bytes"

	"github.com/malivvan/crypto/internal/encoding"
)

const Curve25519GenName = "Curve25519"

type CurveInfo struct {
	GenName string
	Oid     *encoding.OID
	Curve   Curve
}

var Curves = []CurveInfo{
	{
		// Curve25519 (X25519 ECDH)
		GenName: Curve25519GenName,
		Oid:     encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}),
		Curve:   NewCurve25519(),
	},
	{
		// Ed25519
		GenName: Curve25519GenName,
		Oid:     encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}),
		Curve:   NewEd25519(),
	},
}

func FindByCurve(curve Curve) *CurveInfo {
	for _, curveInfo := range Curves {
		if curveInfo.Curve.GetCurveName() == curve.GetCurveName() {
			return &curveInfo
		}
	}
	return nil
}

func FindByOid(oid encoding.Field) *CurveInfo {
	var rawBytes = oid.Bytes()
	for _, curveInfo := range Curves {
		if bytes.Equal(curveInfo.Oid.Bytes(), rawBytes) {
			return &curveInfo
		}
	}
	return nil
}

func FindEdDSAByGenName(curveGenName string) EdDSACurve {
	for _, curveInfo := range Curves {
		if curveInfo.GenName == curveGenName {
			curve, ok := curveInfo.Curve.(EdDSACurve)
			if ok {
				return curve
			}
		}
	}
	return nil
}

func FindECDHByGenName(curveGenName string) ECDHCurve {
	for _, curveInfo := range Curves {
		if curveInfo.GenName == curveGenName {
			curve, ok := curveInfo.Curve.(ECDHCurve)
			if ok {
				return curve
			}
		}
	}
	return nil
}
