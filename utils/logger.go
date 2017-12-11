package utils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type LogFile struct {
	Conf         *Config
	l            *log.Logger
	f            *os.File
	fileDate     string
	logTimestamp bool
	logMutex     *sync.Mutex
}

func (self *LogFile) Init(logTimestamp bool) error {
	self.logMutex = &sync.Mutex{}
	if true == self.Conf.DebugOutput {
		self.l = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
		return nil
	}

	err := self.dirCreateIfNotExists(self.Conf.LogFile)
	if nil != err {
		return err
	}

	self.logTimestamp = logTimestamp
	err = self.openLogFile()
	if nil != err {
		return err
	}

	self.fileDate = time.Now().Format("20060102")
	return nil
}

func (self *LogFile) Println(v ...interface{}) {
	self.logMutex.Lock()
	if false == self.Conf.DebugOutput && self.fileDate != time.Now().Format("20060102") {
		self.rotateLogs()
	}
	err := self.l.Output(len(v), fmt.Sprintln(v...))
	if nil != err {
		fmt.Println(err.Error())
		self.f.Close()
		self.openLogFile()
	}
	self.logMutex.Unlock()
}

func (self *LogFile) Printf(str string, v ...interface{}) {
	self.logMutex.Lock()
	if false == self.Conf.DebugOutput && self.fileDate != time.Now().Format("20060102") {
		self.rotateLogs()
	}
	err := self.l.Output(1, fmt.Sprintf(str, v...))
	if nil != err {
		fmt.Println(err.Error())
		self.f.Close()
		self.openLogFile()
	}
	self.logMutex.Unlock()
}

func (self *LogFile) dirCreateIfNotExists(FileName string) error {
	dir := path.Dir(FileName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0777)
		if nil != err {
			return errors.New(fmt.Sprintf("error creating the log directory: %s", err.Error()))
		}
	}
	return nil
}

func (self *LogFile) openLogFile() error {
	f, err := os.OpenFile(self.Conf.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if nil != err {
		return errors.New(fmt.Sprintf("error opening logfile: %s", err.Error()))
	}
	self.f = f

	if self.logTimestamp {
		self.l = log.New(self.f, "", log.Ldate|log.Lmicroseconds)
	} else {
		self.l = log.New(self.f, "", 0)
	}

	return nil
}

func (self *LogFile) rotateLogs() {
	fileDate := time.Now().Format("20060102")
	FileName := path.Base(self.Conf.LogFile)
	newFileName := path.Dir(self.Conf.LogFile) + "/" + fileDate + "/" + FileName

	err := self.dirCreateIfNotExists(newFileName)
	if nil != err {
		fmt.Println(err.Error())
		return
	}

	self.f.Sync()
	self.f.Close()

	err = os.Rename(self.Conf.LogFile, newFileName)
	if nil != err {
		fmt.Println(err.Error())
		return
	}

	self.fileDate = fileDate

	err = self.openLogFile()
	if nil != err {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// async compress & cleanup old logs
	go self.compressFile(newFileName)
	go filepath.Walk(path.Dir(self.Conf.LogFile), self.RemoveOldLogs)
}

func (self *LogFile) compressFile(FileName string) {
	var cmd string = fmt.Sprintf("/bin/gzip %s", FileName)
	parts := strings.Fields(cmd)
	head := parts[0]
	parts = parts[1:len(parts)]
	output, err := exec.Command(head, parts...).CombinedOutput()

	if err != nil {
		self.Printf("Error compressing log file %s: %s: %s\n", FileName, err.Error(), string(output))
	}
}

func (self *LogFile) RemoveOldLogs(dirPath string, f os.FileInfo, err error) error {
	if err != nil || !f.IsDir() {
		return nil
	}

	dirDate, err := time.Parse("20060102", f.Name())
	if nil == err && dirDate.Before(time.Now().AddDate(0, 0, -10)) {
		self.l.Println("removing old log directory:", dirPath)
		err = os.RemoveAll(dirPath)
		if nil != err {
			self.l.Println("error removing old log dir:", err.Error())
		}
	}

	return nil
}
