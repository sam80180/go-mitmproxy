package helper

import (
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

func SysCreateTime() (int64, error) {
	p, errP := process.NewProcess(int32(os.Getpid()))
	if errP != nil {
		return 0, errP
	} // end if
	return p.CreateTime()
} // end SysCreateTime()

func SysUpTime() (time.Duration, error) {
	createTime, errCtime := SysCreateTime()
	if errCtime != nil {
		return 0, errCtime
	} // end if
	start := time.UnixMilli(createTime)
	return time.Since(start), nil
} // end SysUpTime()
