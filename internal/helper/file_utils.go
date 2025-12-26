package helper

import "os"

func PathExistsOrStat(path string) (os.FileInfo, bool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return stat, !os.IsNotExist(err), err
	} // end if
	return stat, true, err
} // end PathExistsOrStat()

func PathExists(path string) bool {
	_, e, _ := PathExistsOrStat(path)
	return e
} // end PathExists()
