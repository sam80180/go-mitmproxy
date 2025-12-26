package snmp

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/sirupsen/logrus"
	"github.com/slayercat/GoSNMPServer"
)

const (
	APACHE2_MIB_OID_PREFIX         string = "1.3.6.1.4.1.19786.1.1"
	SNMPD_DEFAULT_PORT             int    = 161
	SNMPD_DEFAULT_COMMUNITY        string = "public"
	SNMPD_DEFAULT_REFRESH_INTERVAL string = "30s"
)

func StartSnmpd(addr, community, proxyAddr, proxyVersion string, extraOIDs []*GoSNMPServer.PDUValueControlItem) {
	_, proxyPort, _ := helper.ParseHostAndPort(proxyAddr)
	if community == "" {
		community = SNMPD_DEFAULT_COMMUNITY
	} // end if
	subagent := GoSNMPServer.SubAgent{
		CommunityIDs: []string{community},
	}
	subagent.OIDs = append(subagent.OIDs, &GoSNMPServer.PDUValueControlItem{
		Document: "serverVersion",
		OID:      fmt.Sprintf("%s.1.2.0", APACHE2_MIB_OID_PREFIX),
		OnGet: func() (value any, err error) {
			return proxyVersion, nil
		},
		Type: gosnmp.OctetString,
	}, &GoSNMPServer.PDUValueControlItem{
		Document: "serverRestart",
		OID:      fmt.Sprintf("%s.1.4.0", APACHE2_MIB_OID_PREFIX),
		OnGet: func() (value any, err error) {
			createTime, errCtime := helper.SysCreateTime()
			if errCtime != nil {
				return "N/A", errCtime
			} // end if
			start := time.UnixMilli(createTime)
			return start.Format(time.RFC3339), nil
		},
		Type: gosnmp.OctetString,
	}, &GoSNMPServer.PDUValueControlItem{
		Document: "totalServerPorts",
		OID:      fmt.Sprintf("%s.1.9.0", APACHE2_MIB_OID_PREFIX),
		OnGet: func() (value any, err error) {
			return 1, nil
		},
		Type: gosnmp.Integer,
	}, &GoSNMPServer.PDUValueControlItem{
		Document: "serverPortIndex",
		OID:      fmt.Sprintf("%s.1.10.1.1.%d", APACHE2_MIB_OID_PREFIX, proxyPort),
		OnGet: func() (value any, err error) {
			return proxyPort, nil
		},
		Type: gosnmp.Integer,
	}, &GoSNMPServer.PDUValueControlItem{
		Document: "serverPortNumber",
		OID:      fmt.Sprintf("%s.1.10.1.2.%d", APACHE2_MIB_OID_PREFIX, proxyPort),
		OnGet: func() (value any, err error) {
			return proxyPort, nil
		},
		Type: gosnmp.Integer,
	}, &GoSNMPServer.PDUValueControlItem{
		Document: "serverStatus",
		OID:      fmt.Sprintf("%s.2.5.0", APACHE2_MIB_OID_PREFIX),
		OnGet: func() (value any, err error) {
			return 1, nil
		},
		Type: gosnmp.Integer,
	}, &GoSNMPServer.PDUValueControlItem{
		Document: "serverUptime",
		OID:      fmt.Sprintf("%s.2.6.0", APACHE2_MIB_OID_PREFIX),
		OnGet: func() (value any, err error) {
			t, e := helper.SysUpTime()
			return t.String(), e
		},
		Type: gosnmp.OctetString,
	})
	if len(extraOIDs) > 0 {
		subagent.OIDs = append(subagent.OIDs, extraOIDs...)
	} // end if
	master := GoSNMPServer.MasterAgent{
		Logger:    logrus.StandardLogger(),
		SubAgents: []*GoSNMPServer.SubAgent{&subagent},
	}
	server := GoSNMPServer.NewSNMPServer(master)
	err := server.ListenUDP("udp", addr)
	if err != nil {
		logrus.Errorf("Error in listen: %+v", err)
	} // end if
	server.ServeForever()
} // end StartSnmpd()

/*
References:
https://github.com/eplx/mod_apache_snmp/blob/master/mib/APACHE2-MIB.TXT
https://mod-apache-snmp.sourceforge.net/english/APACHE2-MIB.TXT
*/
