package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Config struct {
	DebugOutput bool   `json:"debug_output"`
	LogFile     string `json:"log_file"`
}

func (self *Config) Load(ConfigFilePath string) {
	contents, err := ioutil.ReadFile(ConfigFilePath)
	if nil != err {
		fmt.Printf("Unable to open the config file: %s\n", err.Error())
		os.Exit(1)
	}

	err = json.Unmarshal(contents, self)
	if nil != err {
		fmt.Println("unable to read the config file:", err.Error())
		os.Exit(1)
	}
}
