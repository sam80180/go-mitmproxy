package helper

import (
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
	"github.com/talkincode/toughradius/v8/common/snmp/mibs/ruijie"
)

func GetSNMPIfIndex(g *gosnmp.GoSNMP, ifName string) (uint32, error) {
	result, errWalk := g.WalkAll(ruijie.PoeInfaceNameOidPrefix)
	if errWalk != nil {
		return 0, errWalk
	} // end if
	for _, pdu := range result {
		if pdu.Type == gosnmp.OctetString && string(pdu.Value.([]byte)) == ifName {
			pp := strings.Split(pdu.Name, ".")
			ifIndex, _ := strconv.Atoi(pp[len(pp)-1])
			return uint32(ifIndex), nil
		} // end if
	} // end for
	return 0, nil
} // end GetSNMPIfIndex()
