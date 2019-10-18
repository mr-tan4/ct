package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	_ "github.com/lib/pq"
	"golang.org/x/net/context"
	"net/http"
	"sync"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "189213"
	dbname   = "ct"
)

func main() {
	GetEntries()
	//todo 写入数据库
	//todo 由 python 进行解析

}

// 单次执行的任务
func GetEntries() {

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	lc, err := client.New("https://ct.googleapis.com/logs/argon2019/", &http.Client{}, jsonclient.Options{})
	if err != nil {
		fmt.Print("connection error ")
	}
	treehead, err := lc.GetSTH(context.Background())
	if err != nil {
		fmt.Print("error in treehead")
	}

	run := func(size int) {
		var counts int
		length := 256
		if size <= length {
			counts = 1
		} else if size%length != 0 {
			counts = (size / length) + 1
		} else {
			counts = size / length
		}
		var wd sync.WaitGroup
		for count := 0; count < counts; count++ {
			wd.Add(1)
			go func() {
				defer wd.Done()
				leaves, err := lc.GetEntries(context.Background(), int64(count*length), int64((count*length)+length))
				if err != nil {
					fmt.Println("error in getEntries", err)
				}
				for _, v := range leaves {
					switch v.Leaf.TimestampedEntry.EntryType {
					case ct.X509LogEntryType:
						data := base64.StdEncoding.EncodeToString(v.X509Cert.Raw)
						sql := "insert into cert_schema.cert_data(cert_data) values ('" + data + "');"
						db.Exec(sql)
					case ct.PrecertLogEntryType:
						data := base64.StdEncoding.EncodeToString(v.Precert.TBSCertificate.Raw)
						sql := "insert into cert_schema.cert_data(cert_data) values ('" + data + "');"
						db.Exec(sql)
					default:
					}
				}
			}()
		}
		wd.Wait()
	}
	run(int(treehead.TreeSize))
}
