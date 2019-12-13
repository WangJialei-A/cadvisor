// +build linux

package fs

// #include <unistd.h>
// #include <sys/types.h>
// #include <linux/perf_event.h>
// #include <stdint.h>
// #include <errno.h>
// #include <sys/sysinfo.h>
//
// uint32_t def_PERF_ATTR_SIZE_VER5 = PERF_ATTR_SIZE_VER5;
//
// void set_attr_disabled(struct perf_event_attr *attr, int disabled) {
// 	attr->disabled = disabled;
// }
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"log"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

var numCPU int

func init() {
	numCPU = int(C.get_nprocs())
}

type PerfData struct {
	file            *os.File
	fds             [][]uintptr
	perfLastValue   [][]uint64
	perfLastEnabled []uint64
	perfLastRunning []uint64
}

type PerfEventGroup struct {
	lock *sync.Mutex
	// cgroup path -> data
	perfData map[string]*PerfData
}

func NewPerfEventGroup() *PerfEventGroup {
	return &PerfEventGroup{&sync.Mutex{}, make(map[string]*PerfData)}
}

func (s *PerfEventGroup) Name() string {
	return "perf_event"
}

func (s *PerfEventGroup) Apply(d *cgroupData) error {
	// we just want to join this group even though we don't set anything
	if _, err := d.join("perf_event"); err != nil && !cgroups.IsNotFound(err) {
		return err
	}
	return nil
}

func (s *PerfEventGroup) Set(path string, cgroup *configs.Cgroup) error {
	return nil
}

func (s *PerfEventGroup) Remove(d *cgroupData) error {
	path, _ := d.path("perf_event")
	if pd, ok := s.perfData[path]; ok {
		for i := 0; i < numCPU; i++ {
			for j := 0; j < len(peCounters); j++ {
				syscall.Close(int(pd.fds[i][j]))
			}
		}
		pd.file.Close()
		delete(s.perfData, path)
	}
	return removePath(d.path("perf_event"))
}

func (s *PerfEventGroup) GetStats(path string, stats *cgroups.Stats) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if pd, ok := s.perfData[path]; !ok {
		// first time
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		fds := make([][]uintptr, numCPU)
		for i := 0; i < numCPU; i++ {
			fds[i] = make([]uintptr, len(peCounters))
			fds[i][0], err = openPerfLeader(f.Fd(), uintptr(i), peCounters[0])
			if err != nil {
				return err
			}
			for j := 1; j < len(peCounters); j++ {
				fds[i][j], err = openPerfFollower(fds[i][0], f.Fd(), uintptr(i), peCounters[j])
				if err != nil {
					return err
				}
				if err := startPerf(fds[i][j]); err != nil {
					return err
				}
			}
			if err := startPerf(fds[i][0]); err != nil {
				return err
			}
		}
		pd = &PerfData{
			file: f,
			fds:  fds,
		}

		s.perfData[path] = pd
	} else {
		newData := make([][]uint64, numCPU)
		enabled := make([]uint64, numCPU)
		running := make([]uint64, numCPU)
		for i := 0; i < numCPU; i++ {
			var err error
			newData[i], enabled[i], running[i], err = readPerf(pd.fds[i][0])
			if err != nil {
				log.Print(err)
				continue
			}
		}
		var res []uint64
		if pd.perfLastValue != nil {
			res = make([]uint64, len(peCounters))
			for i := 0; i < numCPU; i++ {
				for j := 0; j < len(peCounters); j++ {
					if enabled[i]-pd.perfLastEnabled[i] != 0 {
						res[j] += uint64(float64(newData[i][j]-pd.perfLastValue[i][j]) / float64(enabled[i]-pd.perfLastEnabled[i]) * float64(running[i]-pd.perfLastRunning[i]))
					}
				}
			}
			stats.PerfStats.Cycle = res[0]
			stats.PerfStats.Instruction = res[1]
		}
		pd.perfLastValue = newData
		pd.perfLastEnabled = enabled
		pd.perfLastRunning = running
	}
	return nil
}

type PerfEventCounter struct {
	EventCode, UMask                      uint
	EventName                             string
	CounterMask, Invert, EdgeDetect, PEBS uint
}

var peCounters = []PerfEventCounter{{
	EventCode: 0x3c,
	UMask:     0x0,
	EventName: "CPU_CLK_UNHALTED.THREAD_P",
}, {
	EventCode: 0xc0,
	UMask:     0x0,
	EventName: "INST_RETIRED.ANY_P",
}}

func (pec *PerfEventCounter) getConfig() C.__u64 {
	return C.__u64(pec.EventCode |
		(pec.UMask << 8) |
		(pec.EdgeDetect << 18) |
		(pec.Invert << 23) |
		(pec.CounterMask << 24))
}

func perfEventOpen(attr C.struct_perf_event_attr,
	pid, cpu, groupFd, flags uintptr) (uintptr, error) {
	fd, _, err := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&attr)),
		pid, cpu, groupFd, flags, 0)

	if err != 0 {
		return 0, errors.New("fail to open perf event")
	}
	return fd, nil
}

func ioctl(fd, req, arg uintptr) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
	if err != 0 {
		return errors.New("fail to ioctl")
	}
	return nil
}

type perfStruct struct {
	Size        uint64
	TimeEnabled uint64
	TimeRunning uint64
	Data        [10]struct {
		Value uint64
		ID    uint64
	}
}

func openPerfLeader(cgroupFd uintptr, cpu uintptr, pec PerfEventCounter) (uintptr, error) {
	perfAttr := C.struct_perf_event_attr{
		_type:       C.__u32(C.PERF_TYPE_RAW),
		size:        C.__u32(C.def_PERF_ATTR_SIZE_VER5),
		config:      pec.getConfig(),
		sample_type: C.PERF_SAMPLE_IDENTIFIER,
		read_format: C.PERF_FORMAT_GROUP |
			C.PERF_FORMAT_TOTAL_TIME_ENABLED |
			C.PERF_FORMAT_TOTAL_TIME_RUNNING |
			C.PERF_FORMAT_ID,
	}
	C.set_attr_disabled(&perfAttr, 1)
	return perfEventOpen(perfAttr, cgroupFd, cpu, ^uintptr(0), C.PERF_FLAG_PID_CGROUP|C.PERF_FLAG_FD_CLOEXEC)
}

func openPerfFollower(leader uintptr, cgroupFd uintptr, cpu uintptr, pec PerfEventCounter) (uintptr, error) {
	perfAttr := C.struct_perf_event_attr{
		_type:       C.__u32(C.PERF_TYPE_RAW),
		size:        C.__u32(C.def_PERF_ATTR_SIZE_VER5),
		config:      pec.getConfig(),
		sample_type: C.PERF_SAMPLE_IDENTIFIER,
		read_format: C.PERF_FORMAT_GROUP |
			C.PERF_FORMAT_TOTAL_TIME_ENABLED |
			C.PERF_FORMAT_TOTAL_TIME_RUNNING |
			C.PERF_FORMAT_ID,
	}
	C.set_attr_disabled(&perfAttr, 1)
	return perfEventOpen(perfAttr, ^uintptr(0), cpu, leader, C.PERF_FLAG_FD_CLOEXEC)
}

func startPerf(fd uintptr) error {
	err := ioctl(fd, C.PERF_EVENT_IOC_RESET, 0)
	if err != nil {
		return err
	}
	err = ioctl(fd, C.PERF_EVENT_IOC_ENABLE, 0)
	if err != nil {
		return err
	}
	return nil
}

func stopPerf(fd uintptr) error {
	return ioctl(fd, C.PERF_EVENT_IOC_DISABLE, 0)
}

func readPerf(fd uintptr) ([]uint64, uint64, uint64, error) {
	res := make([]uint64, len(peCounters))
	b := make([]byte, 1000)
	_, err := syscall.Read(int(fd), b)
	if err != nil {
		return nil, 0, 0, err
	}
	var result perfStruct
	binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &result)

	for i := 0; i < len(res); i++ {
		res[i] += result.Data[i].Value
	}

	return res, result.TimeEnabled, result.TimeRunning, nil
}
