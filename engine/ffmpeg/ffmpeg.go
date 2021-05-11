package ffmpeg

import (
	"fmt"
	"github.com/xfrr/goffmpeg/transcoder"
	"log"
	"path"
	"sync"
)

var mm = make(map[string]float64)

var mutex sync.RWMutex

func Tomp4(inputPath, outputPath string) {
	log.Println("input-output:", inputPath, outputPath)
	outputPath = outputPath + ".mp4"
	mutex.RLock()
	key := path.Base(outputPath)
	defer mutex.RUnlock()
	if t := mm[key]; t != 0 {
		log.Println("is doing ", inputPath)
		return
	}

	trans := new(transcoder.Transcoder)

	//fpath := ffmpeg.Configuration{FfprobeBin: "E:/worktool/ffmpeg/bin/ffprobe.exe ", FfmpegBin: "E:/worktool/ffmpeg/bin/ffmpeg.exe "}
	//trans.SetConfiguration(fpath)
	err := trans.Initialize(inputPath, outputPath)
	log.Println("err:", err)
	//trans.MediaFile().SetResolution("320x240")
	//trans.MediaFile().SetVideoCodec("xvid")
	trans.MediaFile().SetResolution("320x240")
	trans.MediaFile().SetVideoBitRate("400k")
	trans.MediaFile().SetFrameRate(25)

	go func() {
		done := trans.Run(true)
		fmt.Print(done)
		progress := trans.Output()
		for msg := range progress {
			mm[key] = msg.Progress
			fmt.Println(msg)
		}
		delete(mm, key)
	}()

}

func ListProgress(key string) float64 {
	//res := make(map[string]float64)
	//for transs := range mm {
	//	out := mm[transs]
	//	num := <-out
	//	filenameWithSuffix := path.Base(transs) + ".mp4"
	//	fmt.Println("get file", filenameWithSuffix)
	//	res[filenameWithSuffix] = num.Progress
	//}
	//return res
	if out := mm[key]; out != 0 {
		return out
	}
	return 0

}
